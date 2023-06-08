package cluster

// poc_test.go contains proof of concept tests for the byte-range locking logic.
// This goes directly to an underlying filesystem without going through gocryptfs.

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// Check that byte-range locks work on an empty file
func TestPoCFcntlFlock(t *testing.T) {
	path := test_helpers.TmpDir + "/" + t.Name()

	fd1, err := syscall.Open(path, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd1)

	// F_OFD_SETLK locks on the same fd always succeed, so we have to
	// open a 2nd time.
	fd2, err := syscall.Open(path, syscall.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd2)

	lk := unix.Flock_t{
		Type:   unix.F_WRLCK,
		Whence: unix.SEEK_SET,
		Start:  0,
		Len:    0,
	}
	err = unix.FcntlFlock(uintptr(fd1), unix.F_OFD_SETLK, &lk)
	if err != nil {
		t.Fatal(err)
	}
	err = unix.FcntlFlock(uintptr(fd2), unix.F_OFD_SETLK, &lk)
	if err == nil {
		t.Fatal("double-lock succeeded but should have failed")
	}
}

// See if we can get garbage data when the file header is read and written concurrently.
// We should get either 0 bytes or 18 correct bytes.
func TestPoCHeaderCreation(t *testing.T) {
	path := test_helpers.TmpDir + "/" + t.Name()
	var wg sync.WaitGroup
	// I ran this with 10000 iteration and no problems to be seen. Let's not waste too
	// much testing time.
	const loops = 100

	var stats struct {
		readOk    int64
		readEmpty int64
		writes    int64
	}

	writeBuf := []byte("123456789012345678")
	if len(writeBuf) != contentenc.HeaderLen {
		t.Fatal("BUG wrong header length")
	}

	writerThread := func() {
		defer wg.Done()
		for i := 0; i < loops; i++ {
			if t.Failed() {
				return
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
			if err != nil {
				t.Errorf("BUG: this should not happen: open err=%v", err)
				return
			}
			// Do like gocryptfs does and prealloc the 18 bytes
			err = syscallcompat.EnospcPrealloc(int(f.Fd()), 0, contentenc.HeaderLen)

			_, err = f.WriteAt(writeBuf, 0)
			if err != nil {
				t.Errorf("iteration %d: Pwrite: %v", i, err)
			}
			atomic.AddInt64(&stats.writes, 1)
			f.Close()
			syscall.Unlink(path)
		}
	}

	readerThread := func() {
		defer wg.Done()
		for i := 0; i < loops; i++ {
			if t.Failed() {
				return
			}
			f, err := os.OpenFile(path, os.O_RDONLY, 0600)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Error(err)
				return
			}
			readBuf := make([]byte, contentenc.HeaderLen)
			_, err = f.ReadAt(readBuf, 0)
			if errors.Is(err, io.EOF) {
				atomic.AddInt64(&stats.readEmpty, 1)
				goto close
			}
			if err != nil {
				t.Errorf("iteration %d: ReadAt: %v", i, err)
				goto close
			}
			if !bytes.Equal(writeBuf, readBuf) {
				t.Errorf("iteration %d: corrupt data received: %x", i, readBuf)
				goto close
			}
			atomic.AddInt64(&stats.readOk, 1)
		close:
			f.Close()
		}
	}

	wg.Add(2)
	go writerThread()
	go readerThread()
	wg.Wait()

	t.Logf("readEmpty=%d readOk=%d writes=%d", stats.readEmpty, stats.readOk, stats.writes)
}

// TestPoCTornWrite simulates what TestConcurrentCreate does.
//
// Fails on ext4, quoting https://stackoverflow.com/a/35256626 :
// > Linux 4.2.6 with ext4: update atomicity = 1 byte
//
// Passes on XFS.
func TestPoCTornWrite(t *testing.T) {
	if os.Getenv("ENABLE_CLUSTER_TEST") != "1" {
		t.Skipf("This test is disabled by default because it fails unless on XFS.\n" +
			"Run it like this: ENABLE_CLUSTER_TEST=1 go test\n" +
			"Choose a backing directory by setting TMPDIR.")
	}

	path := test_helpers.TmpDir + "/" + t.Name()
	var wg sync.WaitGroup
	const loops = 10000

	writerThread := func() {
		defer wg.Done()
		for i := 0; i < loops; i++ {
			if t.Failed() {
				return
			}

			f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Errorf("BUG: this should not happen: open err=%v", err)
				return
			}

			// Write
			blockData := bytes.Repeat([]byte{byte(i)}, 42)
			if _, err = f.WriteAt(blockData, 0); err != nil {
				t.Errorf("iteration %d: WriteAt: %v", i, err)
				return
			}

			// Readback and verify
			readBuf := make([]byte, 100)
			if n, err := f.ReadAt(readBuf, 0); err == io.EOF {
				readBuf = readBuf[:n]
			} else if err != nil {
				t.Error(err)
				return
			}
			if len(readBuf) != len(blockData) {
				t.Error("wrong length")
				return
			}
			for _, v := range readBuf {
				if v != readBuf[0] {
					t.Errorf("iteration %d: inconsistent block: %x", i, readBuf)
					return
				}
			}
			f.Close()
		}
	}

	wg.Add(2)
	go writerThread()
	go writerThread()
	wg.Wait()
}
