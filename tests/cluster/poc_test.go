package cluster

// poc_test.go contains proof of concept tests for the byte-range locking logic.
// This goes directly to an underlying filesystem without going through gocryptfs.

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

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
