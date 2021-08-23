package defaults

import (
	"io/ioutil"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestDirIVRace(t *testing.T) {
	// Create "dir1" with one file in it
	dir1 := test_helpers.DefaultPlainDir + "/TestDirIVRace_Dir1"
	err := os.Mkdir(dir1, 0700)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(dir1+"/file", nil, 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Create directory "dir2"
	dir2 := test_helpers.DefaultPlainDir + "/TestDirIVRace_Dir2"
	err = os.Mkdir(dir2, 0700)
	if err != nil {
		t.Fatal(err)
	}
	file2 := dir2 + "/file"
	err = ioutil.WriteFile(file2, nil, 0600)
	if err != nil {
		t.Fatal(err)
	}

	var stop int32
	defer func() { atomic.StoreInt32(&stop, 1) }()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		wg.Done()
		for {
			// Keep dir2 in the diriv cache
			fd, err2 := os.Open(file2)
			if err2 == nil {
				fd.Close()
			}
			if atomic.LoadInt32(&stop) != 0 {
				return
			}
		}
	}()
	wg.Wait()
	time.Sleep(time.Millisecond)

	// Overwrite dir2 with dir1
	err = syscall.Unlink(file2)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Rename(dir1, dir2)
	if err != nil {
		t.Fatal(err)
	}
	// We should be able to stat file2
	_, err = os.Stat(file2)
	if err != nil {
		t.Error(err)
	}
}
