package matrix

import (
	"bytes"
	"io"
	"log"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
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
	buf := make([]byte, 100)
	content := []byte("1234567890")
	threads := 10
	loops := 30
	for i := 0; i < threads; i++ {
		// Reader thread
		wg.Add(1)
		go func() {
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
	// "Creater" thread
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
			if err == io.EOF {
				i++
				continue
			}
			if err != nil {
				log.Fatal(err)
			}
			buf := buf0[:n]
			if bytes.Compare(buf, content) != 0 {
				log.Fatal("content mismatch")
			}
			f.Close()
		}
		wg.Done()
	}()
	wg.Wait()
}
