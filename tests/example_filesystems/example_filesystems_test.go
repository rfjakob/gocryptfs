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
	"os/exec"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

var opensslOpt string

// tmpFsPath contains a private writeable copy of the example_filesystems
// folder.
var tmpFsPath string

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

		// Create a private copy of the example filesystems that we can
		// mess with
		cmd := exec.Command("cp", "-a", "../example_filesystems", test_helpers.TmpDir)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		err := cmd.Run()
		if err != nil {
			fmt.Printf("cp -a failed: %v\n", err)
			os.Exit(1)
		}
		tmpFsPath = test_helpers.TmpDir + "/example_filesystems/"

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
	cDir = tmpFsPath + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test", opensslOpt)
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
	}
}

// This filesystem is not supported anymore.
func TestExampleFSv05(t *testing.T) {
	cDir := "v0.5"
	pDir := test_helpers.TmpDir + "/" + cDir
	cDir = tmpFsPath + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test", opensslOpt)
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
	}
}

// This filesystem is not supported anymore.
func TestExampleFSv06(t *testing.T) {
	cDir := "v0.6"
	pDir := test_helpers.TmpDir + "/" + cDir
	cDir = tmpFsPath + cDir
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo test", opensslOpt)
	if err == nil {
		t.Errorf("Mounting too old FS should fail")
	}
}

// This filesystem is not supported anymore.
func TestExampleFSv06PlaintextNames(t *testing.T) {
	cDir := "v0.6-plaintextnames"
	pDir := test_helpers.TmpDir + "/" + cDir
	cDir = tmpFsPath + cDir
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
	cDir = tmpFsPath + cDir
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
	cDir = tmpFsPath + cDir

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
	cDir = tmpFsPath + cDir
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
	cDir = tmpFsPath + cDir
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
	dirA = tmpFsPath + dirA
	test_helpers.MountOrFatal(t, dirA, dirB, "-reverse", "-extpass", "echo test", opensslOpt)
	c := dirB + "/gocryptfs.conf"
	if !test_helpers.VerifyExistence(t, c) {
		t.Errorf("%s missing", c)
	}
	test_helpers.MountOrFatal(t, dirB, dirC, "-extpass", "echo test", opensslOpt)
	checkExampleFSrw(t, dirC, false)
	test_helpers.UnmountPanic(dirC)
	test_helpers.UnmountPanic(dirB)

	m := "68b51855-042abd80-635ae1ba-90152a78-2ec2d243-832ac72a-eab0561a-f2d37913"
	test_helpers.MountOrFatal(t, dirA, dirB, "-reverse", "-masterkey", m,
		"-raw64=false", "-hkdf=false", opensslOpt)
	if !test_helpers.VerifyExistence(t, c) {
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
	dirA = tmpFsPath + dirA
	test_helpers.MountOrFatal(t, dirA, dirB, "-reverse", "-extpass", "echo test", opensslOpt)
	c := dirB + "/gocryptfs.conf"
	if !test_helpers.VerifyExistence(t, c) {
		t.Errorf("%s missing", c)
	}
	test_helpers.MountOrFatal(t, dirB, dirC, "-extpass", "echo test", opensslOpt)
	checkExampleFSrw(t, dirC, false)
	test_helpers.UnmountPanic(dirC)
	test_helpers.UnmountPanic(dirB)

	m := "e7fb8f0d-2a81df9e-26611e4b-5540b218-e48aa458-c2a623af-d0c82637-1466b5f2"
	test_helpers.MountOrFatal(t, dirA, dirB, "-reverse", "-masterkey", m,
		"-raw64=false", "-hkdf=false", opensslOpt)
	if !test_helpers.VerifyExistence(t, c) {
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
	cDir = tmpFsPath + cDir
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

// Check that the masterkey=stdin cli option works.
func TestExampleFSv13MasterkeyStdin(t *testing.T) {
	cDir := "v1.3"
	pDir := test_helpers.TmpDir + "/TestExampleFSv13MasterkeyStdin.mnt"
	cDir = tmpFsPath + cDir
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-q", "-masterkey=stdin", opensslOpt, cDir, pDir}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	p, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Start()
	if err != nil {
		t.Error(err)
	}
	// Write masterkey to stdin
	p.Write([]byte("fd890dab-86bf61cf-ec5ad460-ad3ed01f-9c52d546-2a31783d-a56b088d-3d05232e"))
	p.Close()
	err = cmd.Wait()
	if err != nil {
		t.Error(err)
	}
	// Check that the fs decrypts ok & unmount
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)
}

// gocryptfs v1.3 introduced HKDF.
// We check the md5 sum of the encrypted version of a file to make sure we don't
// accidentally change the ciphertext generation.
// Create a full crypto round-trip by mounting two times:
// dirA -> reverse mount -> dirB -> forward mount -> dirC
func TestExampleFSv13reverse(t *testing.T) {
	var R_OK uint32 = 4
	// Prepare directories
	dirA := "v1.3-reverse"
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
	dirA = tmpFsPath + dirA
	// Mount using password
	// We pass "-wpanic=false" because the '..' and '.' tests deliverately trigger warnings
	test_helpers.MountOrFatal(t, dirA, dirB, "-reverse", "-extpass", "echo test", "-wpanic=false", opensslOpt)
	c := dirB + "/gocryptfs.conf"
	if !test_helpers.VerifyExistence(t, c) {
		t.Errorf("%s missing", c)
	}
	test_helpers.MountOrFatal(t, dirB, dirC, "-extpass", "echo test", opensslOpt)
	// Test
	checkExampleFSrw(t, dirC, false)
	// Access to encrypted version of '..' should fail
	cPath := dirB + "/D8VwRPqWW8x7M5OEoMs0Eg"
	err = syscall.Access(cPath, R_OK)
	if err != syscall.ENOENT {
		t.Errorf("want ENOENT, got: %v", err)
	}
	// Access to encrypted version of '.' should fail
	cPath = dirB + "/kkmARPseVj4XQFW-EL42-w"
	err = syscall.Access(cPath, R_OK)
	if err != syscall.ENOENT {
		t.Errorf("want ENOENT, got: %v", err)
	}
	// Encrypted version of dir1/dir2/file (10000 zero bytes)
	cPath = dirB + "/zOsW1-BUX54hC2hmhu2EOw/4ZqrpGQdw5r07KR1qw2ZeQ/tfCm9Sp9J_Dvc-jD7J6p8g"
	want := "9818501d214c5eb42ca2472caf6c82a1"
	actual := test_helpers.Md5fn(cPath)
	if actual != want {
		t.Errorf("wrong md5")
	}
	// Unmount
	test_helpers.UnmountPanic(dirC)
	test_helpers.UnmountPanic(dirB)

	// Mount using masterkey
	m := "2290a7f4-3e1908fb-b006f7d9-261bdaf1-4b72bc38-3b24956c-db7d8a8d-d996076a"
	test_helpers.MountOrFatal(t, dirA, dirB, "-reverse", "-masterkey", m, opensslOpt)
	if !test_helpers.VerifyExistence(t, c) {
		t.Errorf("%s missing", c)
	}
	test_helpers.MountOrFatal(t, dirB, dirC, "-aessiv", "-masterkey", m, opensslOpt)
	// Test
	checkExampleFSrw(t, dirC, false)
	actual = test_helpers.Md5fn(cPath)
	if actual != want {
		t.Errorf("wrong md5")
	}
	// Unmmount
	test_helpers.UnmountPanic(dirC)
	test_helpers.UnmountPanic(dirB)
}

// gocryptfs v2.2 introduced -deterministic-names
func TestExampleFSv22deterministicNames(t *testing.T) {
	cDir := "v2.2-deterministic-names"
	pDir := test_helpers.TmpDir + "/" + cDir
	cDir = tmpFsPath + cDir
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test", opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)

	pDir = pDir + "_m"
	test_helpers.MountOrFatal(t, cDir, pDir, "-deterministic-names", "-masterkey",
		"722733f5-b0f399f5-5465ad7a-f0bed125-"+
			"e82de7b4-045e7608-a5e5c78e-04a1a61e",
		opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)
}

// gocryptfs v2.2 introduced -xchacha
func TestExampleFSv22xchacha(t *testing.T) {
	cDir := "v2.2-xchacha"
	pDir := test_helpers.TmpDir + "/" + cDir
	cDir = tmpFsPath + cDir
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test", opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)

	pDir = pDir + "_m"
	test_helpers.MountOrFatal(t, cDir, pDir, "-xchacha", "-masterkey",
		"44670e7e-32475bfc-bdfb8a8c-be17a767-"+
			"0679cac0-be705d8c-af41c411-28c40f26",
		opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)
}

// gocryptfs v2.2 introduced -xchacha and -deterministic-names
func TestExampleFSv22xchachaDeterministicNames(t *testing.T) {
	cDir := "v2.2-xchacha-deterministic-names"
	pDir := test_helpers.TmpDir + "/" + cDir
	cDir = tmpFsPath + cDir
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test", opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)

	pDir = pDir + "_m"
	test_helpers.MountOrFatal(t, cDir, pDir, "-xchacha", "-deterministic-names", "-masterkey",
		"beba88a9-c6cd1dc0-b69c6f9d-9daea493-"+
			"9ae87082-4ffc40bf-b44e52db-3933af39",
		opensslOpt)
	checkExampleFSLongnames(t, pDir)
	test_helpers.UnmountPanic(pDir)
}
