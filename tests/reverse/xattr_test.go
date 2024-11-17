package reverse_test

import (
	"fmt"
	"os"
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
	return err2.Err != syscall.EOPNOTSUPP
}

func TestXattrList(t *testing.T) {
	if !xattrSupported(dirA) {
		t.Skip()
	}
	fnA := filepath.Join(dirA, t.Name())
	err := os.WriteFile(fnA, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	val := []byte("xxxxxxxxyyyyyyyyyyyyyyyzzzzzzzzzzzzz")
	num := 20
	namesA := map[string]string{}
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
	namesC := map[string]string{}
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
