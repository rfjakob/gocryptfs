package example_filesystems

// Mount example filesystems and check that the file "status.txt" is there

import (
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

const statusTxtContent = "It works!\n"

func TestMain(m *testing.M) {
	test_helpers.ResetTmpDir(true)
	os.Exit(m.Run())
}

// This filesystem is not supported anymore.
func TestExampleFSv04(t *testing.T) {
	cDir := "v0.4"
	pDir := test_helpers.TmpDir + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test")
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
	}
}

// This filesystem is not supported anymore.
func TestExampleFSv05(t *testing.T) {
	cDir := "v0.5"
	pDir := test_helpers.TmpDir + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test")
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
	}
}

// This filesystem is not supported anymore.
func TestExampleFSv06(t *testing.T) {
	cDir := "v0.6"
	pDir := test_helpers.TmpDir + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test")
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
	}
}

// This filesystem is not supported anymore.
func TestExampleFSv06PlaintextNames(t *testing.T) {
	cDir := "v0.6-plaintextnames"
	pDir := test_helpers.TmpDir + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test")
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
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
