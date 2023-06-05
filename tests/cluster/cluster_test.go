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

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// This test passes on XFS but fails on ext4 and tmpfs!!!
//
// Quoting https://lists.samba.org/archive/samba-technical/2019-March/133050.html
//
// > It turns out that xfs respects POSIX w.r.t "atomic read/write" and
// > this is implemented by taking a file-wide shared lock on every
// > buffered read.
// > This behavior is unique to XFS on Linux and is not optional.
// > Other Linux filesystems only guaranty page level atomicity for
// > buffered read/write.
//
// See also:
//   - https://lore.kernel.org/linux-xfs/20190325001044.GA23020@dastard/
//     Dave Chinner: XFS is the only linux filesystem that provides this behaviour.
func TestClusterConcurrentRW(t *testing.T) {
	if os.Getenv("ENABLE_CLUSTER_TEST") != "1" {
		t.Skipf("This test is disabled by default because it fails unless on XFS.\n" +
			"Run it like this: ENABLE_CLUSTER_TEST=1 go test\n" +
			"Choose a backing directory by setting TMPDIR.")
	}

	const blocksize = contentenc.DefaultBS
	const fileSize = 25 * blocksize // 100 kiB

	cDir := test_helpers.InitFS(t)
	mnt1 := cDir + ".mnt1"
	mnt2 := cDir + ".mnt2"
	test_helpers.MountOrFatal(t, cDir, mnt1, "-extpass=echo test", "-wpanic=0")
	defer test_helpers.UnmountPanic(mnt1)
	test_helpers.MountOrFatal(t, cDir, mnt2, "-extpass=echo test", "-wpanic=0")
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
		buf := make([]byte, blocksize)
		for i := 0; i < loops; i++ {
			if t.Failed() {
				return
			}
			off := rand.Int63n(fileSize / blocksize)
			_, err := f.WriteAt(buf, off)
			if err != nil {
				t.Errorf("writeThread iteration %d: WriteAt failed: %v", i, err)
				return
			}
		}
	}
	readThread := func(f *os.File) {
		defer wg.Done()
		zeroBlock := make([]byte, blocksize)
		buf := make([]byte, blocksize)
		for i := 0; i < loops; i++ {
			if t.Failed() {
				return
			}
			off := rand.Int63n(fileSize / blocksize)
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
