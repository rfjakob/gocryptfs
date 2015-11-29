package integration_tests

// Mount example filesystems and check that the file "status.txt" is there

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

const statusTxtContent = "It works!\n"

// checkStatusTxt - read file "filename" and verify that it contains
// "It works!\n"
func checkExampleContent(t *testing.T, dir string) {
	// Check regular file
	statusFile := filepath.Join(dir, "status.txt")
	contentBytes, err := ioutil.ReadFile(statusFile)
	if err != nil {
		t.Fatal(err)
	}
	content := string(contentBytes)
	if content != statusTxtContent {
		t.Errorf("Unexpected content: %s\n", content)
	}
	// Check relative symlink
	symlink := filepath.Join(dir, "rel")
	target, err := os.Readlink(symlink)
	if err != nil {
		t.Fatal(err)
	}
	if target != "status.txt" {
		t.Errorf("Unexpected link target: %s\n", target)
	}
	// Check absolute symlink
	symlink = filepath.Join(dir, "abs")
	target, err = os.Readlink(symlink)
	if err != nil {
		t.Fatal(err)
	}
	if target != "/a/b/c/d" {
		t.Errorf("Unexpected link target: %s\n", target)
	}
}

// Test example_filesystems/v0.4
// with password mount and -masterkey mount
func TestExampleFsV04(t *testing.T) {
	pDir := tmpDir + "TestExampleFsV04/"
	cDir := "example_filesystems/v0.4"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	mount(cDir, pDir, "-extpass", "echo test")
	checkExampleContent(t, pDir)
	unmount(pDir)
	mount(cDir, pDir, "-masterkey", "74676e34-0b47c145-00dac61a-17a92316-"+
		"bb57044c-e205b71f-65f4fdca-7cabd4b3", "-diriv=false")
	checkExampleContent(t, pDir)
	unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// Test example_filesystems/v0.5
// with password mount and -masterkey mount
func TestExampleFsV05(t *testing.T) {
	pDir := tmpDir + "TestExampleFsV05/"
	cDir := "example_filesystems/v0.5"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	mount(cDir, pDir, "-extpass", "echo test")
	checkExampleContent(t, pDir)
	unmount(pDir)
	mount(cDir, pDir, "-masterkey", "e7f38c71-0da80f68-d3b2cd7d-ee4f49e5-"+
		"f8bc98cd-d7976950-85204c54-3081b302")
	checkExampleContent(t, pDir)
	unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}
