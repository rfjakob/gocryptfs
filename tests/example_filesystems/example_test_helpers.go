package example_filesystems

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

const statusTxtContent = "It works!\n"

// checkExampleFS - verify that "dir" contains the expected test files
func checkExampleFS(t *testing.T, dir string, rw bool) {
	// Read regular file
	statusFile := filepath.Join(dir, "status.txt")
	contentBytes, err := os.ReadFile(statusFile)
	if err != nil {
		t.Error(err)
		return
	}
	content := string(contentBytes)
	if content != statusTxtContent {
		t.Errorf("Unexpected content: %s\n", content)
	}
	// Read relative symlink
	symlink := filepath.Join(dir, "rel")
	target, err := os.Readlink(symlink)
	if err != nil {
		t.Errorf("relative symlink: Readlink: %v", err)
		return
	}
	if target != "status.txt" {
		t.Errorf("relative symlink: Unexpected link target: %s\n", target)
	}
	// Read absolute symlink
	symlink = filepath.Join(dir, "abs")
	target, err = os.Readlink(symlink)
	if err != nil {
		t.Errorf("absolute symlink: Readlink: %v", err)
		return
	}
	if target != "/a/b/c/d" {
		t.Errorf("absolute symlink: Unexpected link target: %s\n", target)
	}
	if rw {
		// Test directory operations
		t.Run("TestRename", func(t *testing.T) { test_helpers.TestRename(t, dir) })
		t.Run("TestMkdirRmdir", func(t *testing.T) { test_helpers.TestMkdirRmdir(t, dir) })
	}
}

// checkExampleFSLongnames - verify that "dir" contains the expected test files
// plus the long file name test file.
// Also tests simple directory operations.
func checkExampleFSLongnames(t *testing.T, dir string) {
	checkExampleFSrw(t, dir, true)
}

// checkExampleFSrw is like checkExampleFSLongnames but gives the caller the
// choice if he wants to run tests that write to the FS.
func checkExampleFSrw(t *testing.T, dir string, rw bool) {
	// regular tests
	checkExampleFS(t, dir, rw)
	// long name test file
	longname := "longname_255_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
		"xxxxxxxxxxxxxxxxxxxxxxxx"
	contentBytes, err := os.ReadFile(filepath.Join(dir, longname))
	if err != nil {
		t.Error(err)
		return
	}
	content := string(contentBytes)
	if content != statusTxtContent {
		t.Errorf("longname_255: unexpected content: %s\n", content)
	}
}
