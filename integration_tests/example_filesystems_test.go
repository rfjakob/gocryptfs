package integration_tests

// Mount example filesystems and check that the file "status.txt" is there

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

const statusTxtContent = "It works!\n"

// checkExampleFS - verify that "dir" contains the expected test files
func checkExampleFS(t *testing.T, dir string) {
	// Read regular file
	statusFile := filepath.Join(dir, "status.txt")
	contentBytes, err := ioutil.ReadFile(statusFile)
	if err != nil {
		t.Fatal(err)
	}
	content := string(contentBytes)
	if content != statusTxtContent {
		t.Errorf("Unexpected content: %s\n", content)
	}
	// Read relative symlink
	symlink := filepath.Join(dir, "rel")
	target, err := os.Readlink(symlink)
	if err != nil {
		t.Fatal(err)
	}
	if target != "status.txt" {
		t.Errorf("Unexpected link target: %s\n", target)
	}
	// Read absolute symlink
	symlink = filepath.Join(dir, "abs")
	target, err = os.Readlink(symlink)
	if err != nil {
		t.Fatal(err)
	}
	if target != "/a/b/c/d" {
		t.Errorf("Unexpected link target: %s\n", target)
	}
	// Test directory operations
	testRename(t, dir)
	testMkdirRmdir(t, dir)
}

// checkExampleFSLongnames - verify that "dir" contains the expected test files
// plus the long file name test file
func checkExampleFSLongnames(t *testing.T, dir string) {
	// regular tests
	checkExampleFS(t, dir)
	// long name test file
	longname := "longname_255_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
		"xxxxxxxxxxxxxxxxxxxxxxxx"
	contentBytes, err := ioutil.ReadFile(filepath.Join(dir, longname))
	if err != nil {
		t.Fatal(err)
	}
	content := string(contentBytes)
	if content != statusTxtContent {
		t.Errorf("longname_255: unexpected content: %s\n", content)
	}

}

// Test example_filesystems/v0.4
// with password mount and -masterkey mount
func TestExampleFSv04(t *testing.T) {
	pDir := tmpDir + "TestExampleFsV04/"
	cDir := "example_filesystems/v0.4"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	mountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	checkExampleFS(t, pDir)
	unmount(pDir)
	mountOrFatal(t, cDir, pDir, "-masterkey", "74676e34-0b47c145-00dac61a-17a92316-"+
		"bb57044c-e205b71f-65f4fdca-7cabd4b3", "-diriv=false", "-emenames=false", "-gcmiv128=false")
	checkExampleFS(t, pDir)
	unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// Test example_filesystems/v0.5
// with password mount and -masterkey mount
func TestExampleFSv05(t *testing.T) {
	pDir := tmpDir + "TestExampleFsV05/"
	cDir := "example_filesystems/v0.5"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	mountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	checkExampleFS(t, pDir)
	unmount(pDir)
	mountOrFatal(t, cDir, pDir, "-masterkey", "199eae55-36bff4af-83b9a3a2-4fa16f65-"+
		"1549ccdb-2d08d1f0-b1b26965-1b61f896", "-emenames=false", "-gcmiv128=false")
	checkExampleFS(t, pDir)
	unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// Test example_filesystems/v0.6
// with password mount and -masterkey mount
func TestExampleFSv06(t *testing.T) {
	pDir := tmpDir + "TestExampleFsV06/"
	cDir := "example_filesystems/v0.6"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	mountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	checkExampleFS(t, pDir)
	unmount(pDir)
	mountOrFatal(t, cDir, pDir, "-masterkey", "7bc8deb0-5fc894ef-a093da43-61561a81-"+
		"0e8dee83-fdc056a4-937c37dd-9df5c520", "-gcmiv128=false")
	checkExampleFS(t, pDir)
	unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// Test example_filesystems/v0.6-plaintextnames
// with password mount and -masterkey mount
// v0.6 changed the file name handling a lot, hence the explicit test case for
// plaintextnames.
func TestExampleFSv06PlaintextNames(t *testing.T) {
	pDir := tmpDir + "TestExampleFsV06PlaintextNames/"
	cDir := "example_filesystems/v0.6-plaintextnames"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	mountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	checkExampleFS(t, pDir)
	unmount(pDir)
	mountOrFatal(t, cDir, pDir, "-masterkey", "f4690202-595e4593-64c4f7e0-4dddd7d1-"+
		"303147f9-0ca8aea2-966341a7-52ea8ae9", "-plaintextnames", "-gcmiv128=false")
	checkExampleFS(t, pDir)
	unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// Test example_filesystems/v0.7
// with password mount and -masterkey mount
// v0.7 adds 128 bit GCM IVs
func TestExampleFSv07(t *testing.T) {
	pDir := tmpDir + "TestExampleFsV07/"
	cDir := "example_filesystems/v0.7"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	mountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	checkExampleFS(t, pDir)
	unmount(pDir)
	mountOrFatal(t, cDir, pDir, "-masterkey", "ed7f6d83-40cce86c-0e7d79c2-a9438710-"+
		"575221bf-30a0eb60-2821fa8f-7f3123bf")
	checkExampleFS(t, pDir)
	unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// Test example_filesystems/v0.9
// (gocryptfs v0.9 introduced long file name support)
func TestExampleFSv09(t *testing.T) {
	cDir := "example_filesystems/v0.9"
	pDir := tmpDir + "TestExampleFsV09/"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	mountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	checkExampleFSLongnames(t, pDir)
	unmount(pDir)
	mountOrFatal(t, cDir, pDir, "-masterkey", "1cafe3f4-bc316466-2214c47c-ecd89bf3-"+
		"4e078fe4-f5faeea7-8b7cab02-884f5e1c")
	checkExampleFSLongnames(t, pDir)
	unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}
