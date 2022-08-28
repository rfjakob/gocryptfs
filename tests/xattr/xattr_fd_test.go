//go:build linux
// +build linux

// Darwin does not support Fgetxattr and friends!

package xattr_tests

import (
	"io/ioutil"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestFdXattr(t *testing.T) {
	attr := "user.foo"
	fn := test_helpers.DefaultPlainDir + "/TestFdXattr"
	err := ioutil.WriteFile(fn, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	fd, err := syscall.Open(fn, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	buf := make([]byte, 1000)
	sz, err := unix.Flistxattr(fd, buf)
	if err != nil {
		t.Error(err)
	} else if sz != 0 {
		t.Errorf("expected zero size, got %d", sz)
	}
	val1 := []byte("123456789")
	unix.Fsetxattr(fd, attr, val1, 0)
	sz, err = unix.Flistxattr(fd, buf)
	if err != nil {
		t.Fatal(err)
	}
	// Length of "user.attr" + terminating null byte
	expectedSz := len(attr) + 1
	if sz != expectedSz {
		t.Errorf("expected size %d, got %d", expectedSz, sz)
	}
	str := ""
	if sz > 0 {
		str = string(buf[:sz-1])
	}
	if str != attr {
		t.Errorf("expected name %q, got %q", attr, str)
	}
	// Check content
	sz, err = unix.Fgetxattr(fd, attr, buf)
	if err != nil {
		t.Fatal(err)
	}
	str = string(buf[:sz])
	if str != string(val1) {
		t.Errorf("expected val %q, got %q", val1, str)
	}
	// Delete value
	err = unix.Fremovexattr(fd, attr)
	if err != nil {
		t.Error(err)
	}
	sz, err = unix.Flistxattr(fd, buf)
	if err != nil {
		t.Error(err)
	} else if sz != 0 {
		t.Errorf("expected zero size, got %d", sz)
	}
}
