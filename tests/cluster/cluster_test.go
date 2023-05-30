// package cluster_test finds out what happens if multiple
// gocryptfs mounts write to one file concurrently
// (usually, nothing good).
//
// This use case is relevant for HPC clusters.
package cluster_test

import (
	"bytes"
	"math/rand"
	"os"
	"sync"
	"testing"

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
// * https://lore.kernel.org/linux-xfs/20190325001044.GA23020@dastard/
//   Dave Chinner: XFS is the only linux filesystem that provides this behaviour.
func TestClusterConcurrentRW(t *testing.T) {
	if os.Getenv("ENABLE_CLUSTER_TEST") != "1" {
		t.Skipf("This test is disabled by default because it fails unless on XFS.\n" +
			"Run it like this: ENABLE_CLUSTER_TEST=1 go test\n" +
			"Choose a backing directory by setting TMPDIR.")
	}

	const blocksize = 4096
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
