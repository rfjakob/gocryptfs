package defaults

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/pkg/xattr"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

// On modern Linux distributions, /tmp may be on tmpfs,
// which does not support user xattrs. Try /var/tmp instead.
var alternateTestParentDir = "/var/tmp/gocryptfs-xattr-test-parent"

func TestMain(m *testing.M) {
	if !xattrSupported(test_helpers.TmpDir) {
		test_helpers.SwitchTestParentDir(alternateTestParentDir)
	}
	if !xattrSupported(test_helpers.TmpDir) {
		fmt.Printf("xattrs not supported on %q", test_helpers.TmpDir)
		os.Exit(1)
	}
	test_helpers.ResetTmpDir(true)
	test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, "-zerokey")
	r := m.Run()
	test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
	os.RemoveAll(test_helpers.TmpDir)
	os.Exit(r)
}

func TestXattrSetGetRm(t *testing.T) {
	attr := "user.foo"
	fn := test_helpers.DefaultPlainDir + "/TestXattrSetGetRm"
	err := ioutil.WriteFile(fn, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	// Set
	val1 := []byte("123456789")
	err = xattr.Set(fn, attr, val1)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val2, err := xattr.Get(fn, attr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(val1, val2) {
		t.Fatalf("wrong readback value: %v != %v", val1, val2)
	}
	// Remove
	err = xattr.Remove(fn, attr)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val3, err := xattr.Get(fn, attr)
	if err == nil {
		t.Fatalf("attr is still there after deletion!? val3=%v", val3)
	}
}

func TestXattrSetEmpty(t *testing.T) {
	attr := "user.foo"
	fn := test_helpers.DefaultPlainDir + "/TestXattrSetEmpty1"
	err := ioutil.WriteFile(fn, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	// Make sure it does not exist already
	_, err = xattr.Get(fn, attr)
	if err == nil {
		t.Fatal("we should have got an error here")
	}
	// Set empty value
	err = xattr.Set(fn, attr, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val, err := xattr.Get(fn, attr)
	if err != nil {
		t.Fatal(err)
	}
	if len(val) != 0 {
		t.Errorf("wrong length: want=0 have=%d", len(val))
	}
	// Overwrite empty value with something
	val1 := []byte("xyz123")
	err = xattr.Set(fn, attr, val1)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val2, err := xattr.Get(fn, attr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(val1, val2) {
		t.Fatalf("wrong readback value: %v != %v", val1, val2)
	}
	// Overwrite something with empty value
	err = xattr.Set(fn, attr, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val, err = xattr.Get(fn, attr)
	if err != nil {
		t.Fatal(err)
	}
	if len(val) != 0 {
		t.Errorf("wrong length: want=0 have=%d", len(val2))
	}
}

func TestXattrList(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestXattrList"
	err := ioutil.WriteFile(fn, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	val := []byte("xxxxxxxxyyyyyyyyyyyyyyyzzzzzzzzzzzzz")
	num := 20
	for i := 1; i <= num; i++ {
		attr := fmt.Sprintf("user.TestXattrList.%02d", i)
		err = xattr.Set(fn, attr, val)
		if err != nil {
			t.Fatal(err)
		}
	}
	names, err := xattr.List(fn)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != num {
		t.Errorf("wrong number of names, want=%d have=%d", num, len(names))
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "user.TestXattrList.") {
			t.Errorf("unexpected attr name: %q", n)
		}
	}
}

func xattrSupported(path string) bool {
	_, err := xattr.Get(path, "user.xattrSupported-dummy-value")
	if err == nil {
		return true
	}
	err2 := err.(*xattr.Error)
	if err2.Err == syscall.EOPNOTSUPP {
		return false
	}
	return true
}
