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

	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

const statusTxtContent = "It works!\n"

var opensslOpt string

func TestMain(m *testing.M) {
	// Make "testing.Verbose()" return the correct value
	flag.Parse()
	variants := []string{"-openssl=false"}
	if !stupidgcm.BuiltWithoutOpenssl {
		variants = append(variants, "-openssl=true")
	} else {
		fmt.Println("Skipping OpenSSL tests, I have been compiled without openssl support")
	}
	for _, opensslOpt = range variants {
		if testing.Verbose() {
			fmt.Printf("example_filesystems: testing with %q\n", opensslOpt)
		}
		test_helpers.ResetTmpDir(false)
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
		"-raw64=false", "-hkdf=false", opensslOpt)
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
		"-raw64=false", "-hkdf=false", opensslOpt)
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
		"-raw64=false", "-hkdf=false", opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)
}

// gocryptfs v1.1 introduced AES-SIV
func TestExampleFSv11(t *testing.T) {
	cDir := "v1.1-aessiv"
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
		"eaf371c3-f9a55336-8819f22b-7bccd7c2-a738cf61-7261c658-14c28a03-9428992b",
		"-aessiv", "-raw64=false", "-hkdf=false", opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)
}

// gocryptfs v1.1 introduced reverse mode
func TestExampleFSv11reverse(t *testing.T) {
	dirA := "v1.1-reverse"
	dirB := test_helpers.TmpDir + "/" + dirA + ".B"
	err := os.Mkdir(dirB, 0700)
	if err != nil {
		t.Fatal(err)
	}
	dirC := test_helpers.TmpDir + "/" + dirA + ".C"
	err = os.Mkdir(dirC, 0700)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, dirA, dirB, "-reverse", "-extpass", "echo test", opensslOpt)
	c := dirB + "/gocryptfs.conf"
	if !test_helpers.VerifyExistence(c) {
		t.Errorf("%s missing", c)
	}
	test_helpers.MountOrFatal(t, dirB, dirC, "-extpass", "echo test", opensslOpt)
	checkExampleFSrw(t, dirC, false)
	test_helpers.UnmountPanic(dirC)
	test_helpers.UnmountPanic(dirB)

	m := "68b51855-042abd80-635ae1ba-90152a78-2ec2d243-832ac72a-eab0561a-f2d37913"
	test_helpers.MountOrFatal(t, dirA, dirB, "-reverse", "-masterkey", m,
		"-raw64=false", "-hkdf=false", opensslOpt)
	if !test_helpers.VerifyExistence(c) {
		t.Errorf("%s missing", c)
	}
	test_helpers.MountOrFatal(t, dirB, dirC, "-aessiv", "-masterkey", m,
		"-raw64=false", "-hkdf=false", opensslOpt)
	checkExampleFSrw(t, dirC, false)
	test_helpers.UnmountPanic(dirC)
	test_helpers.UnmountPanic(dirB)
}

// gocryptfs v1.1 introduced reverse mode
func TestExampleFSv11reversePlaintextnames(t *testing.T) {
	dirA := "v1.1-reverse-plaintextnames"
	dirB := test_helpers.TmpDir + "/" + dirA + ".B"
	err := os.Mkdir(dirB, 0700)
	if err != nil {
		t.Fatal(err)
	}
	dirC := test_helpers.TmpDir + "/" + dirA + ".C"
	err = os.Mkdir(dirC, 0700)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, dirA, dirB, "-reverse", "-extpass", "echo test", opensslOpt)
	c := dirB + "/gocryptfs.conf"
	if !test_helpers.VerifyExistence(c) {
		t.Errorf("%s missing", c)
	}
	test_helpers.MountOrFatal(t, dirB, dirC, "-extpass", "echo test", opensslOpt)
	checkExampleFSrw(t, dirC, false)
	test_helpers.UnmountPanic(dirC)
	test_helpers.UnmountPanic(dirB)

	m := "e7fb8f0d-2a81df9e-26611e4b-5540b218-e48aa458-c2a623af-d0c82637-1466b5f2"
	test_helpers.MountOrFatal(t, dirA, dirB, "-reverse", "-masterkey", m,
		"-raw64=false", "-hkdf=false", opensslOpt)
	if !test_helpers.VerifyExistence(c) {
		t.Errorf("%s missing", c)
	}
	test_helpers.MountOrFatal(t, dirB, dirC, "-aessiv", "-masterkey", m,
		"-raw64=false", "-hkdf=false", opensslOpt)
	checkExampleFSrw(t, dirC, false)
	test_helpers.UnmountPanic(dirC)
	test_helpers.UnmountPanic(dirB)
}

// gocryptfs v1.3 introduced HKDF
func TestExampleFSv13(t *testing.T) {
	cDir := "v1.3"
	pDir := test_helpers.TmpDir + "/" + cDir
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test", opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)

	pDir = pDir + "_m"
	test_helpers.MountOrFatal(t, cDir, pDir, "-masterkey",
		"fd890dab-86bf61cf-ec5ad460-ad3ed01f-9c52d546-2a31783d-a56b088d-3d05232e",
		opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)
}
