package reverse_test

import (
	"os"
	"testing"
	//"time"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func TestLongnameStat(t *testing.T) {
	fd, err := os.Create(dirA + "/" + x240)
	if err != nil {
		t.Fatal(err)
	}
	path := dirC + "/" + x240
	if !test_helpers.VerifyExistence(path) {
		t.Fail()
	}
	test_helpers.VerifySize(t, path, 0)
	_, err = fd.Write(make([]byte, 10))
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	/*
		time.Sleep(1000 * time.Millisecond)
		test_helpers.VerifySize(t, path, 10)
	*/
}

func TestSymlinks(t *testing.T) {
	target := "/"
	os.Symlink(target, dirA+"/symlink")
	cSymlink := dirC + "/symlink"
	_, err := os.Lstat(cSymlink)
	if err != nil {
		t.Errorf("Lstat: %v", err)
	}
	_, err = os.Stat(cSymlink)
	if err != nil {
		t.Errorf("Stat: %v", err)
	}
	actualTarget, err := os.Readlink(cSymlink)
	if err != nil {
		t.Fatal(err)
	}
	if target != actualTarget {
		t.Errorf("wrong symlink target: want=%q have=%q", target, actualTarget)
	}
}
