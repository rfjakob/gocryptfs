package matrix

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// Test Mkdir and Rmdir
func TestMkdirRmdir(t *testing.T) {
	test_helpers.TestMkdirRmdir(t, test_helpers.DefaultPlainDir)
}

// Overwrite an empty directory with another directory
func TestDirOverwrite(t *testing.T) {
	dir1 := test_helpers.DefaultPlainDir + "/DirOverwrite1"
	dir2 := test_helpers.DefaultPlainDir + "/DirOverwrite2"
	err := os.Mkdir(dir1, 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Mkdir(dir2, 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Rename(dir1, dir2)
	if err != nil {
		t.Fatal(err)
	}
}

// Test that we can create and remove a directory regardless of the permission it has
// https://github.com/rfjakob/gocryptfs/issues/354
func TestRmdirPerms(t *testing.T) {
	for _, perm := range []uint32{0000, 0100, 0200, 0300, 0400, 0500, 0600, 0700} {
		dir := fmt.Sprintf("TestRmdir%#o", perm)
		path := test_helpers.DefaultPlainDir + "/" + dir
		err := syscall.Mkdir(path, perm)
		if err != nil {
			t.Fatalf("Mkdir %q: %v", dir, err)
		}
		err = syscall.Rmdir(path)
		if err != nil {
			t.Fatalf("Rmdir %q: %v", dir, err)
		}
	}
}

// TestHaveDotdot checks that we have "." and ".." in a directory.
// (gocryptfs v2.0-beta1 did not!)
func TestHaveDotdot(t *testing.T) {
	dir1 := test_helpers.DefaultPlainDir + "/TestHaveDotdot"
	err := os.Mkdir(dir1, 0700)
	if err != nil {
		t.Fatal(err)
	}
	// All Go readdir functions filter out "." and "..".
	// Fall back to "ls -a" which does not.
	out, err := exec.Command("ls", "-a", dir1).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	have := string(out)
	want := ".\n..\n"
	if have != want {
		t.Errorf("have=%q want=%q", have, want)
	}
}
