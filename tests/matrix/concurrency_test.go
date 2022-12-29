package matrix

import (
	"bytes"
	"io"
	"log"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// https://github.com/rfjakob/gocryptfs/issues/363
//
// Note: this test calls log.Fatal() instead of t.Fatal() because apparently,
// calling t.Fatal() from a goroutine hangs the test.
func TestConcurrentReadWrite(t *testing.T) {
	var wg sync.WaitGroup
	fn := test_helpers.DefaultPlainDir + "/TestConcurrentReadWrite"
	if f, err := os.Create(fn); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	content := []byte("1234567890")
	threads := 10
	loops := 30
	for i := 0; i < threads; i++ {
		// Reader thread
		wg.Add(1)
		go func() {
			buf := make([]byte, 100)
			fRd, err := os.Open(fn)
			if err != nil {
				log.Fatal(err)
			}
			for j := 0; j < loops; j++ {
				n, err := fRd.ReadAt(buf, 0)
				if err != nil && err != io.EOF {
					log.Fatal(err)
				}
				if n != 0 && n != 10 {
					log.Fatalf("strange read length: %d", n)
				}
			}
			fRd.Close()
			wg.Done()
		}()

		// Writer thread
		wg.Add(1)
		go func() {
			fWr, err := os.OpenFile(fn, os.O_RDWR, 0700)
			if err != nil {
				log.Fatal(err)
			}
			for j := 0; j < loops; j++ {
				err = fWr.Truncate(0)
				if err != nil {
					log.Fatal(err)
				}
				_, err = fWr.WriteAt(content, 0)
				if err != nil {
					log.Fatal(err)
				}
			}
			fWr.Close()
			wg.Done()
		}()
	}
	wg.Wait()
}

// https://github.com/rfjakob/gocryptfs/issues/363
//
// Note: this test calls log.Fatal() instead of t.Fatal() because apparently,
// calling t.Fatal() from a goroutine hangs the test.
func TestConcurrentReadCreate(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestConcurrentReadCreate"
	content := []byte("1234567890")
	loops := 100
	var wg sync.WaitGroup
	// "Create()" thread
	wg.Add(1)
	go func() {
		for i := 0; i < loops; i++ {
			f, err := os.Create(fn)
			if err != nil {
				log.Fatal(err)
			}
			_, err = f.Write(content)
			if err != nil {
				log.Fatal(err)
			}
			f.Close()
			syscall.Unlink(fn)
		}
		wg.Done()
	}()
	// "Reader" thread
	wg.Add(1)
	go func() {
		buf0 := make([]byte, 100)
		for i := 0; i < loops; i++ {
			f, err := os.Open(fn)
			if err != nil {
				i++
				continue
			}
			n, err := f.Read(buf0)
			f.Close()
			if err == io.EOF {
				i++
				continue
			}
			if err != nil {
				log.Fatal(err)
			}
			buf := buf0[:n]
			if !bytes.Equal(buf, content) {
				// Calling t.Fatal() from a goroutine hangs the test so we use log.Fatal
				log.Fatalf("%s: content mismatch: have=%q want=%q", t.Name(), string(buf), string(content))
			}
		}
		wg.Done()
	}()
	wg.Wait()
}

// TestInoReuse tries to uncover problems when a file gets replaced by
// a directory with the same inode number (and vice versa).
//
// So far, it only has triggered warnings like this
//
//	go-fuse: warning: Inode.Path: inode i4201033 is orphaned, replacing segment with ".go-fuse.5577006791947779410/deleted"
//
// but none of the "blocked waiting for FORGET".
func TestInoReuse(t *testing.T) {
	var wg sync.WaitGroup
	fn := test_helpers.DefaultPlainDir + "/" + t.Name()

	wg.Add(1)
	go func() {
		for i := 0; i < 1000; i++ {
			fd, err := syscall.Open(fn, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC, 0600)
			if err == syscall.EISDIR {
				continue
			}
			if err != nil {
				t.Error(err)
				break
			}
			var st syscall.Stat_t
			syscall.Fstat(fd, &st)
			if i%2 == 0 {
				syscall.Close(fd)
				syscall.Unlink(fn)
			} else {
				syscall.Unlink(fn)
				syscall.Close(fd)

			}
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		for i := 0; i < 1000; i++ {
			err := syscall.Mkdir(fn, 0700)
			if err == syscall.EEXIST {
				continue
			}
			if err != nil {
				t.Error(err)
				break
			}
			var st syscall.Stat_t
			syscall.Stat(fn, &st)
			syscall.Rmdir(fn)
		}
		wg.Done()
	}()
	wg.Wait()
}
