package example_filesystems

// Mount example filesystems, check that the example content (normal file, symlinks)
// is there and test mkdir and rmdir
//
// Runs all the tests twice, once with "-openssl=false" and once with
// "-openssl=true".

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

const statusTxtContent = "It works!\n"

var opensslOpt string

func TestMain(m *testing.M) {
	// Make "testing.Verbose()" return the correct value
	flag.Parse()
	for _, opensslOpt = range []string{"-openssl=false", "-openssl=true"} {
		if testing.Verbose() {
			fmt.Printf("example_filesystems: testing with %q\n", opensslOpt)
		}
		test_helpers.ResetTmpDir(true)
		r := m.Run()
		if r != 0 {
			os.Exit(r)
		}
	}
	os.Exit(0)
}

// This filesystem is not supported anymore.
func TestExampleFSv04(t *testing.T) {
	cDir := "v0.4"
	pDir := test_helpers.TmpDir + "/" + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test", opensslOpt)
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
	}
}

// This filesystem is not supported anymore.
func TestExampleFSv05(t *testing.T) {
	cDir := "v0.5"
	pDir := test_helpers.TmpDir + "/" + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test", opensslOpt)
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
	}
}

// This filesystem is not supported anymore.
func TestExampleFSv06(t *testing.T) {
	cDir := "v0.6"
	pDir := test_helpers.TmpDir + "/" + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test", opensslOpt)
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
	}
}

// This filesystem is not supported anymore.
func TestExampleFSv06PlaintextNames(t *testing.T) {
	cDir := "v0.6-plaintextnames"
	pDir := test_helpers.TmpDir + "/" + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test", opensslOpt)
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
	}
}

// Test example_filesystems/v0.7
// with password mount and -masterkey mount
// v0.7 adds 128 bit GCM IVs
func TestExampleFSv07(t *testing.T) {
	cDir := "v0.7"
	pDir := test_helpers.TmpDir + "/" + cDir
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test", opensslOpt)
	checkExampleFS(t, pDir, true)
	test_helpers.UnmountPanic(pDir)
	test_helpers.MountOrFatal(t, cDir, pDir, "-masterkey",
		"ed7f6d83-40cce86c-0e7d79c2-a9438710-575221bf-30a0eb60-2821fa8f-7f3123bf",
		opensslOpt)
	checkExampleFS(t, pDir, true)
	test_helpers.UnmountPanic(pDir)
}

// gocryptfs v0.7 filesystem created with "-plaintextnames"
func TestExampleFSv07PlaintextNames(t *testing.T) {
	cDir := "v0.7-plaintextnames"
	pDir := test_helpers.TmpDir + "/" + cDir + ".mnt"

	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test", opensslOpt)
	checkExampleFS(t, pDir, true)
	test_helpers.UnmountPanic(pDir)
	// The actual unmount takes some time, this causes weird problems. Just don't
	// reuse the mountpoint.
	pDir = pDir + ".2"
	test_helpers.MountOrFatal(t, cDir, pDir, "-plaintextnames", "-masterkey",
		"6d96397b-585631e1-c7cba69d-61e738b6-4d5ad2c2-e21f0fb3-52f60d3a-b08526f7",
		opensslOpt)
	checkExampleFS(t, pDir, true)
	test_helpers.UnmountPanic(pDir)
}

// Test example_filesystems/v0.9
// (gocryptfs v0.9 introduced long file name support)
func TestExampleFSv09(t *testing.T) {
	cDir := "v0.9"
	pDir := test_helpers.TmpDir + "/" + cDir
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test", opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)
	pDir = pDir + ".2"
	test_helpers.MountOrFatal(t, cDir, pDir, "-masterkey",
		"1cafe3f4-bc316466-2214c47c-ecd89bf3-4e078fe4-f5faeea7-8b7cab02-884f5e1c",
		opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)
}
