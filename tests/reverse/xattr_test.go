package reverse_test

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/pkg/xattr"
)

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

func TestXattrList(t *testing.T) {
	t.Skip("TODO: not implemented yet in reverse mode")

	if !xattrSupported(dirA) {
		t.Skip()
	}
	fnA := filepath.Join(dirA, t.Name())
	err := ioutil.WriteFile(fnA, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	val := []byte("xxxxxxxxyyyyyyyyyyyyyyyzzzzzzzzzzzzz")
	num := 20
	var namesA map[string]string
	for i := 1; i <= num; i++ {
		attr := fmt.Sprintf("user.TestXattrList.%02d", i)
		err = xattr.LSet(fnA, attr, val)
		if err != nil {
			t.Fatal(err)
		}
		namesA[attr] = string(val)
	}
	fnC := filepath.Join(dirC, t.Name())
	tmp, err := xattr.LList(fnC)
	if err != nil {
		t.Fatal(err)
	}
	var namesC map[string]string
	for _, n := range tmp {
		namesC[n] = string(val)
	}
	if len(namesA) != len(namesC) {
		t.Errorf("wrong number of names, want=%d have=%d", len(namesA), len(namesC))
	}
	for i := range namesC {
		valA := namesA[i]
		valC := namesC[i]
		if valC != valA {
			t.Errorf("mismatch on attr %q: valA = %q, valC = %q", i, valA, valC)
		}
	}
}
