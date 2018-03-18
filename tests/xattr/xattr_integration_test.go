package defaults

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	xattr "github.com/rfjakob/pkg-xattr"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

// On modern Linux distributions, /tmp may be on tmpfs,
// which does not support user xattrs. Try /var/tmp instead.
var alternateTestParentDir = "/var/tmp/gocryptfs-xattr-test-parent"

func TestMain(m *testing.M) {
	if !xattr.Supported(test_helpers.TmpDir) {
		test_helpers.SwitchTestParentDir(alternateTestParentDir)
	}
	if !xattr.Supported(test_helpers.TmpDir) {
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
