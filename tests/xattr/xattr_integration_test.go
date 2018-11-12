package xattr_tests

// xattr integration tests.
//
// These tests are not integrated into the "matrix" tests because of the need
// to switch TMPDIR to /var/tmp.
// TODO: check if it actually causes trouble in the "matrix" tests.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/pkg/xattr"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func TestMain(m *testing.M) {
	// On modern Linux distributions, /tmp may be on tmpfs,
	// which does not support user xattrs. Try /var/tmp instead
	if !xattrSupported(test_helpers.TmpDir) && os.TempDir() == "/tmp" {
		fmt.Printf("Switching from /tmp to /var/tmp for xattr tests\n")
		test_helpers.SwitchTMPDIR("/var/tmp")
	}
	if !xattrSupported(test_helpers.TmpDir) {
		fmt.Printf("xattrs not supported on %q\n", test_helpers.TmpDir)
		os.Exit(1)
	}
	test_helpers.ResetTmpDir(true)
	// Write deterministic diriv so encrypted filenames are deterministic.
	os.Remove(test_helpers.DefaultCipherDir + "/gocryptfs.diriv")
	diriv := []byte("1234567890123456")
	err := ioutil.WriteFile(test_helpers.DefaultCipherDir+"/gocryptfs.diriv", diriv, 0400)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, "-zerokey")
	r := m.Run()
	test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
	os.RemoveAll(test_helpers.TmpDir)
	os.Exit(r)
}

func setGetRmList(fn string) error {
	// List
	list, err := xattr.LList(fn)
	if err != nil {
		return err
	}
	if len(list) > 0 {
		return fmt.Errorf("Should have gotten empty result, got %v", list)
	}
	attr := "user.foo"
	// Set
	val1 := []byte("123456789")
	err = xattr.LSet(fn, attr, val1)
	if err != nil {
		return err
	}
	// Read back
	val2, err := xattr.LGet(fn, attr)
	if err != nil {
		return err
	}
	if !bytes.Equal(val1, val2) {
		return fmt.Errorf("wrong readback value: %v != %v", val1, val2)
	}
	// Remove
	err = xattr.LRemove(fn, attr)
	if err != nil {
		return err
	}
	// Read back
	val3, err := xattr.LGet(fn, attr)
	if err == nil {
		return fmt.Errorf("attr is still there after deletion!? val3=%v", val3)
	}
	// List
	list, err = xattr.LList(fn)
	if err != nil {
		return err
	}
	if len(list) > 0 {
		return fmt.Errorf("Should have gotten empty result, got %v", list)
	}
	return nil
}

// Test xattr set, get, rm on a regular file.
func TestSetGetRmRegularFile(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestSetGetRmRegularFile"
	err := ioutil.WriteFile(fn, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	err = setGetRmList(fn)
	if err != nil {
		t.Error(err)
	}
}

// Test xattr set, get, rm on a fifo. This should not hang.
func TestSetGetRmFifo(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestSetGetRmFifo"
	err := syscall.Mkfifo(fn, 0700)
	if err != nil {
		t.Fatalf("creating fifo failed: %v", err)
	}
	// We expect to get EPERM, but we should not hang:
	// $ setfattr -n user.foo -v XXXXX fifo
	// setfattr: fifo: Operation not permitted
	setGetRmList(fn)
}

func TestXattrSetEmpty(t *testing.T) {
	attr := "user.foo"
	fn := test_helpers.DefaultPlainDir + "/TestXattrSetEmpty1"
	err := ioutil.WriteFile(fn, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	// Make sure it does not exist already
	_, err = xattr.LGet(fn, attr)
	if err == nil {
		t.Fatal("we should have got an error here")
	}
	// Set empty value
	err = xattr.LSet(fn, attr, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val, err := xattr.LGet(fn, attr)
	if err != nil {
		t.Fatal(err)
	}
	if len(val) != 0 {
		t.Errorf("wrong length: want=0 have=%d", len(val))
	}
	// Overwrite empty value with something
	val1 := []byte("xyz123")
	err = xattr.LSet(fn, attr, val1)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val2, err := xattr.LGet(fn, attr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(val1, val2) {
		t.Fatalf("wrong readback value: %v != %v", val1, val2)
	}
	// Overwrite something with empty value
	err = xattr.LSet(fn, attr, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val, err = xattr.LGet(fn, attr)
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
		err = xattr.LSet(fn, attr, val)
		if err != nil {
			t.Fatal(err)
		}
	}
	names, err := xattr.LList(fn)
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
	_, err := xattr.LGet(path, "user.xattrSupported-dummy-value")
	if err == nil {
		return true
	}
	err2 := err.(*xattr.Error)
	if err2.Err == syscall.EOPNOTSUPP {
		return false
	}
	return true
}

func TestBase64XattrRead(t *testing.T) {
	attrName := "user.test"
	attrName2 := "user.test2"
	encryptedAttrName := "user.gocryptfs.LB1kHHVrX1OEBdLmj3LTKw"
	encryptedAttrName2 := "user.gocryptfs.d2yn5l7-0zUVqviADw-Oyw"
	attrValue := fmt.Sprintf("test.%d", cryptocore.RandUint64())

	fileName := "TestBase64Xattr"
	encryptedFileName := "BaGak7jIoqAZQMlP0N5uCw"

	plainFn := test_helpers.DefaultPlainDir + "/" + fileName
	encryptedFn := test_helpers.DefaultCipherDir + "/" + encryptedFileName
	err := ioutil.WriteFile(plainFn, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	if _, err2 := os.Stat(encryptedFn); os.IsNotExist(err2) {
		t.Fatalf("encrypted file does not exist: %v", err2)
	}
	xattr.LSet(plainFn, attrName, []byte(attrValue))

	encryptedAttrValue, err1 := xattr.LGet(encryptedFn, encryptedAttrName)
	if err1 != nil {
		t.Fatal(err1)
	}

	xattr.LSet(encryptedFn, encryptedAttrName2, encryptedAttrValue)
	plainValue, err := xattr.LGet(plainFn, attrName2)

	if err != nil || string(plainValue) != attrValue {
		t.Fatalf("Attribute binary value decryption error %s != %s %v", string(plainValue), attrValue, err)
	}

	encryptedAttrValue64 := base64.RawURLEncoding.EncodeToString(encryptedAttrValue)
	xattr.LSet(encryptedFn, encryptedAttrName2, []byte(encryptedAttrValue64))

	plainValue, err = xattr.LGet(plainFn, attrName2)
	if err != nil || string(plainValue) != attrValue {
		t.Fatalf("Attribute base64-encoded value decryption error %s != %s %v", string(plainValue), attrValue, err)
	}

	// Remount with -wpanic=false so gocryptfs does not panics when it sees
	// the broken xattrs
	test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
	test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, "-zerokey", "-wpanic=false")

	brokenVals := []string{
		"111",
		"raw-test-long-block123",
		"raw-test-long-block123-xyz11111111111111111111111111111111111111",
		"$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$",
	}
	for _, val := range brokenVals {
		xattr.LSet(encryptedFn, encryptedAttrName2, []byte(val))
		plainValue, err = xattr.LGet(plainFn, attrName2)
		err2, _ := err.(*xattr.Error)
		if err == nil || err2.Err != syscall.EIO {
			t.Fatalf("Incorrect handling of broken data %s %v", string(plainValue), err)
		}
	}
}
