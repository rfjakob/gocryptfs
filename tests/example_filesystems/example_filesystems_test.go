package example_filesystems

// Mount example filesystems and check that the file "status.txt" is there

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

const statusTxtContent = "It works!\n"

func TestMain(m *testing.M) {
	test_helpers.ResetTmpDir(true)
	os.Exit(m.Run())
}

// checkExampleFS - verify that "dir" contains the expected test files
func checkExampleFS(t *testing.T, dir string, rw bool) {
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

	if rw {
		// Test directory operations
		test_helpers.TestRename(t, dir)
		test_helpers.TestMkdirRmdir(t, dir)
	}
}

// checkExampleFSLongnames - verify that "dir" contains the expected test files
// plus the long file name test file
func checkExampleFSLongnames(t *testing.T, dir string) {
	// regular tests
	checkExampleFS(t, dir, true)
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
	pDir := test_helpers.TmpDir + "TestExampleFsV04/"
	cDir := "v0.4"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test")
	if err == nil {
		t.Errorf("Mounting deprecated FS should fail")
	}
	err = test_helpers.Mount(cDir, pDir, false, "-masterkey", "74676e34-0b47c145-00dac61a-17a92316-"+
		"bb57044c-e205b71f-65f4fdca-7cabd4b3", "-diriv=false", "-emenames=false", "-gcmiv128=false")
	if err == nil {
		t.Errorf("Mounting deprecated FS should fail")
	}
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// Test example_filesystems/v0.5
// with password mount and -masterkey mount
func TestExampleFSv05(t *testing.T) {
	pDir := test_helpers.TmpDir + "TestExampleFsV05/"
	cDir := "v0.5"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test")
	if err == nil {
		t.Errorf("Mounting deprecated FS should fail")
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-masterkey", "199eae55-36bff4af-83b9a3a2-4fa16f65-"+
		"1549ccdb-2d08d1f0-b1b26965-1b61f896", "-emenames=false", "-gcmiv128=false")
	checkExampleFS(t, pDir, true)
	test_helpers.Unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// Test example_filesystems/v0.6
// with password mount and -masterkey mount
func TestExampleFSv06(t *testing.T) {
	pDir := test_helpers.TmpDir + "TestExampleFsV06/"
	cDir := "v0.6"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test")
	if err == nil {
		t.Errorf("Mounting deprecated FS should fail")
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-masterkey", "7bc8deb0-5fc894ef-a093da43-61561a81-"+
		"0e8dee83-fdc056a4-937c37dd-9df5c520", "-gcmiv128=false")
	checkExampleFS(t, pDir, true)
	test_helpers.Unmount(pDir)
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
	pDir := test_helpers.TmpDir + "TestExampleFsV06PlaintextNames/"
	cDir := "v0.6-plaintextnames"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test")
	if err == nil {
		t.Errorf("Mounting deprecated FS should fail")
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-masterkey", "f4690202-595e4593-64c4f7e0-4dddd7d1-"+
		"303147f9-0ca8aea2-966341a7-52ea8ae9", "-plaintextnames", "-gcmiv128=false")
	checkExampleFS(t, pDir, true)
	test_helpers.Unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// Test example_filesystems/v0.7
// with password mount and -masterkey mount
// v0.7 adds 128 bit GCM IVs
func TestExampleFSv07(t *testing.T) {
	pDir := test_helpers.TmpDir + "TestExampleFsV07/"
	cDir := "v0.7"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	checkExampleFS(t, pDir, true)
	test_helpers.Unmount(pDir)
	test_helpers.MountOrFatal(t, cDir, pDir, "-masterkey", "ed7f6d83-40cce86c-0e7d79c2-a9438710-"+
		"575221bf-30a0eb60-2821fa8f-7f3123bf")
	checkExampleFS(t, pDir, true)
	test_helpers.Unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// gocryptfs v0.7 filesystem created with "-plaintextnames"
func TestExampleFSv07PlaintextNames(t *testing.T) {
	cDir := "v0.7-plaintextnames"
	pDir := test_helpers.TmpDir + cDir + ".mnt"

	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	checkExampleFS(t, pDir, true)
	test_helpers.Unmount(pDir)

	test_helpers.MountOrFatal(t, cDir, pDir, "-plaintextnames", "-masterkey",
		"6d96397b-585631e1-c7cba69d-61e738b6-4d5ad2c2-e21f0fb3-52f60d3a-b08526f7")
	checkExampleFS(t, pDir, true)
	test_helpers.Unmount(pDir)

	err := os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}

// Test example_filesystems/v0.9
// (gocryptfs v0.9 introduced long file name support)
func TestExampleFSv09(t *testing.T) {
	cDir := "v0.9"
	pDir := test_helpers.TmpDir + "TestExampleFsV09/"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	checkExampleFSLongnames(t, pDir)
	test_helpers.Unmount(pDir)
	test_helpers.MountOrFatal(t, cDir, pDir, "-masterkey", "1cafe3f4-bc316466-2214c47c-ecd89bf3-"+
		"4e078fe4-f5faeea7-8b7cab02-884f5e1c")
	checkExampleFSLongnames(t, pDir)
	test_helpers.Unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}
