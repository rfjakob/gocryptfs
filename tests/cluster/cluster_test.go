// package cluster_test finds out what happens if multiple
// gocryptfs mounts write to one file concurrently
// (usually, nothing good).
//
// This use case is relevant for HPC clusters.
package cluster_test

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// With -sharedstorage (i.e. with fcntl byte-range locks) this test passes on all
// filesystems. Without, it passes on XFS but fails on ext4 and tmpfs.
//
// Quoting https://lists.samba.org/archive/samba-technical/2019-March/133050.html
//
// > It turns out that xfs respects POSIX w.r.t "atomic read/write" and
// > this is implemented by taking a file-wide shared lock on every
// > buffered read.
//
// Note that ext4 actually provides NO ATOMICITY AT ALL.
// Quoting https://stackoverflow.com/a/35256626 :
//
// > Linux 4.2.6 with ext4: update atomicity = 1 byte
//
// TestPoCTornWrite in this package confirms this.
//
// See also:
//   - https://lore.kernel.org/linux-xfs/20190325001044.GA23020@dastard/
//     Dave Chinner: XFS is the only linux filesystem that provides this behaviour.
func TestClusterConcurrentRW(t *testing.T) {
	const fileSize = 100000 // arbitrary unaligned size with a partial block at the end
	const writeSize = 5000  // arbitrary unaligned size that touches two ciphertext blocks
	const readSize = 5000

	cDir := test_helpers.InitFS(t)
	mnt1 := cDir + ".mnt1"
	mnt2 := cDir + ".mnt2"
	test_helpers.MountOrFatal(t, cDir, mnt1, "-extpass=echo test", "-wpanic=0", "-sharedstorage")
	defer test_helpers.UnmountPanic(mnt1)
	test_helpers.MountOrFatal(t, cDir, mnt2, "-extpass=echo test", "-wpanic=0", "-sharedstorage")
	defer test_helpers.UnmountPanic(mnt2)

	f1, err := os.Create(mnt1 + "/foo")
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()
	// Preallocate space
	_, err = f1.WriteAt(make([]byte, fileSize), 0)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := os.OpenFile(mnt2+"/foo", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	var wg sync.WaitGroup

	const loops = 10000
	writeThread := func(f *os.File) {
		defer wg.Done()
		buf := make([]byte, writeSize)
		for i := 0; i < loops; i++ {
			if t.Failed() {
				return
			}
			off := rand.Int63n(int64(fileSize - len(buf) - 1))
			_, err := f.WriteAt(buf, off)
			if err != nil {
				t.Errorf("writeThread iteration %d: WriteAt failed: %v", i, err)
				return
			}
		}
	}
	readThread := func(f *os.File) {
		defer wg.Done()
		zeroBlock := make([]byte, readSize)
		buf := make([]byte, len(zeroBlock))
		for i := 0; i < loops; i++ {
			if t.Failed() {
				return
			}
			off := rand.Int63n(int64(fileSize - len(zeroBlock) - 1))
			_, err := f.ReadAt(buf, off)
			if err != nil {
				t.Errorf("readThread iteration %d: ReadAt failed: %v", i, err)
				return
			}
			if !bytes.Equal(buf, zeroBlock) {
				t.Errorf("readThread iteration %d: data mismatch", i)
				return
			}
		}
	}

	wg.Add(4)
	go writeThread(f1)
	go writeThread(f2)
	go readThread(f1)
	go readThread(f2)
	wg.Wait()
}

// Multiple hosts creating the same file at the same time could
// overwrite each other's file header, leading to data
// corruption. Passing "-sharedstorage" should prevent this.
func TestConcurrentCreate(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	mnt1 := cDir + ".mnt1"
	mnt2 := cDir + ".mnt2"
	test_helpers.MountOrFatal(t, cDir, mnt1, "-extpass=echo test", "-wpanic=0", "-sharedstorage")
	defer test_helpers.UnmountPanic(mnt1)
	test_helpers.MountOrFatal(t, cDir, mnt2, "-extpass=echo test", "-wpanic=0", "-sharedstorage")
	defer test_helpers.UnmountPanic(mnt2)

	var wg sync.WaitGroup
	const loops = 10000

	createOrOpen := func(path string) (f *os.File, err error) {
		// Use the high-level os.Create/OpenFile instead of syscall.Open because we
		// *want* Go's EINTR retry logic. glibc open(2) has similar logic.
		f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
		if err == nil {
			return
		}
		if !errors.Is(err, os.ErrExist) {
			t.Logf("POSIX compliance issue: exclusive create failed with unexpected error: err=%v", errors.Unwrap(err))
		}
		f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err == nil {
			return
		}
		t.Logf("POSIX compliance issue: non-exlusive create failed with err=%v", errors.Unwrap(err))
		return
	}

	workerThread := func(path string) {
		defer wg.Done()
		buf := make([]byte, 10)
		for i := 0; i < loops; i++ {
			if t.Failed() {
				return
			}
			f, err := createOrOpen(path)
			if err != nil {
				// retry
				continue
			}
			defer f.Close()
			_, err = f.WriteAt(buf, 0)
			if err != nil {
				t.Errorf("iteration %d: Pwrite: %v", i, err)
				return
			}
			buf2 := make([]byte, len(buf)+1)
			n, err := f.ReadAt(buf2, 0)
			if err != nil && err != io.EOF {
				t.Errorf("iteration %d: ReadAt: %v", i, err)
				return
			}
			buf2 = buf2[:n]
			if !bytes.Equal(buf, buf2) {
				t.Errorf("iteration %d: corrupt data received: %x", i, buf2)
				return
			}
			syscall.Unlink(path)

			// Close now (not only when the whole loop exists) to avoid exhausting fds.
			// Double-close on happy path is harmless: "Close will return an error if it has already been called"
			f.Close()
		}
	}

	wg.Add(2)
	go workerThread(mnt1 + "/foo")
	go workerThread(mnt2 + "/foo")
	wg.Wait()
}

// Check that opening with O_CREATE|O_TRUNC and writing always works
func TestOpenTruncate(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	mnt1 := cDir + ".mnt1"
	mnt2 := cDir + ".mnt2"
	test_helpers.MountOrFatal(t, cDir, mnt1, "-extpass=echo test", "-wpanic=0", "-sharedstorage")
	defer test_helpers.UnmountPanic(mnt1)
	test_helpers.MountOrFatal(t, cDir, mnt2, "-extpass=echo test", "-wpanic=0", "-sharedstorage")
	defer test_helpers.UnmountPanic(mnt2)

	var wg sync.WaitGroup
	const loops = 100

	writerThread := func(path string) {
		defer wg.Done()
		for i := 0; i < loops; i++ {
			if t.Failed() {
				return
			}
			f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
			if err != nil {
				t.Logf("POSIX compliance issue: non-exlusive create failed with err=%v", errors.Unwrap(err))
				continue
			}
			_, err = f.WriteAt([]byte("foo"), 0)
			if err != nil {
				t.Errorf("iteration %d: WriteAt: %v", i, err)
			}
			f.Close()
		}
	}

	wg.Add(2)
	go writerThread(mnt1 + "/foo")
	go writerThread(mnt2 + "/foo")
	wg.Wait()
}

// mountTwice creates a new filesystem and mounts it twice with -sharedstorage.
func mountTwice(t *testing.T) (mnt1 string, mnt2 string) {
	cDir := test_helpers.InitFS(t)
	mnt1 = cDir + ".mnt1"
	mnt2 = cDir + ".mnt2"
	test_helpers.MountOrFatal(t, cDir, mnt1, "-extpass=echo test", "-wpanic=0", "-sharedstorage")
	t.Cleanup(func() { test_helpers.UnmountPanic(mnt1) })
	test_helpers.MountOrFatal(t, cDir, mnt2, "-extpass=echo test", "-wpanic=0", "-sharedstorage")
	t.Cleanup(func() { test_helpers.UnmountPanic(mnt2) })
	return
}

// With -sharedstorage, truncate to zero keeps the file header because other
// mounts may have the file ID cached. Growing the file to a block-aligned size
// afterwards used to create a new header, replacing the file ID the other
// mount was still using, corrupting everything it wrote afterwards.
func TestGrowAfterTruncateKeepsHeader(t *testing.T) {
	mnt1, mnt2 := mountTwice(t)
	f1, err := os.Create(mnt1 + "/foo")
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()
	if _, err := f1.WriteAt([]byte("xxxxxxxx"), 0); err != nil {
		t.Fatal(err)
	}
	f2, err := os.OpenFile(mnt2+"/foo", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	// Make mount2 cache the file ID
	if _, err := f2.ReadAt(make([]byte, 8), 0); err != nil {
		t.Fatal(err)
	}
	// mount1: truncate to zero, then grow to exactly one block
	if err := f1.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if err := f1.Truncate(4096); err != nil {
		t.Fatal(err)
	}
	// mount2 writes using its cached file ID
	want := []byte("hello")
	if _, err := f2.WriteAt(want, 0); err != nil {
		t.Fatal(err)
	}
	// A fresh open on mount1 (reads the file ID from disk) must see the data
	f3, err := os.Open(mnt1 + "/foo")
	if err != nil {
		t.Fatal(err)
	}
	defer f3.Close()
	buf := make([]byte, len(want))
	if _, err := f3.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(buf, want) {
		t.Errorf("wrong content: got %q, want %q", buf, want)
	}
}

// Write() skips hole padding when a write directly follows the previous one,
// based on process-local state. With -sharedstorage, another mount may have
// shrunk the file in between, leaving the old partial last block unpadded
// in the middle of the file, making it unreadable.
func TestConsecutiveWriteAfterRemoteTruncate(t *testing.T) {
	mnt1, mnt2 := mountTwice(t)
	f1, err := os.Create(mnt1 + "/foo")
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()
	if _, err := f1.WriteAt(bytes.Repeat([]byte("a"), 8192), 0); err != nil {
		t.Fatal(err)
	}
	// mount2 shrinks the file so that the second block is partial
	if err := os.Truncate(mnt2+"/foo", 5000); err != nil {
		t.Fatal(err)
	}
	// mount1 continues writing where it left off, creating a hole
	if _, err := f1.WriteAt(bytes.Repeat([]byte("b"), 4096), 8192); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte("a"), 5000), make([]byte, 8192-5000)...)
	want = append(want, bytes.Repeat([]byte("b"), 4096)...)
	have, err := os.ReadFile(mnt2 + "/foo")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(have, want) {
		t.Errorf("wrong content: len(have)=%d, len(want)=%d", len(have), len(want))
	}
}
