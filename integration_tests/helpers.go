package integration_tests

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/cryptfs"
)

// Note: the code assumes that all have a trailing slash
const tmpDir = "/tmp/gocryptfs_main_test/"
const defaultPlainDir = tmpDir + "plain/"
const defaultCipherDir = tmpDir + "cipher/"

const gocryptfsBinary = "../gocryptfs"

// resetTmpDir - delete old tmp dir, create new one, write gocryptfs.diriv
func resetTmpDir() {
	fu := exec.Command("fusermount", "-z", "-u", defaultPlainDir)
	fu.Run()

	err := os.RemoveAll(tmpDir)
	if err != nil {
		fmt.Println("resetTmpDir: RemoveAll:" + err.Error())
		os.Exit(1)
	}

	err = os.MkdirAll(defaultPlainDir, 0777)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = os.MkdirAll(defaultCipherDir, 0777)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = cryptfs.WriteDirIV(defaultCipherDir)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// mount CIPHERDIR "c" on PLAINDIR "p"
func mount(c string, p string, extraArgs ...string) {
	var args []string
	args = append(args, extraArgs...)
	args = append(args, "-q", "-wpanic")
	//args = append(args, "--fusedebug")
	args = append(args, c)
	args = append(args, p)
	cmd := exec.Command(gocryptfsBinary, args...)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err := cmd.Run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// unmount PLAINDIR "p"
func unmount(p string) error {
	fu := exec.Command("fusermount", "-u", "-z", p)
	fu.Stdout = os.Stdout
	fu.Stderr = os.Stderr
	err := fu.Run()
	if err != nil {
		fmt.Println(err)
	}
	return err
}

// Return md5 string for file "filename"
func md5fn(filename string) string {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("ReadFile: %v\n", err)
		return ""
	}
	return md5hex(buf)
}

// Return md5 string for "buf"
func md5hex(buf []byte) string {
	rawHash := md5.Sum(buf)
	hash := hex.EncodeToString(rawHash[:])
	return hash
}

// Verify that the file size equals "want". This checks:
// 1) Size reported by Stat()
// 2) Number of bytes returned when reading the whole file
func verifySize(t *testing.T, path string, want int) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		t.Errorf("ReadFile failed: %v", err)
	} else if len(buf) != want {
		t.Errorf("wrong read size: got=%d want=%d", len(buf), want)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Errorf("Stat failed: %v", err)
	} else if fi.Size() != int64(want) {
		t.Errorf("wrong stat file size, got=%d want=%d", fi.Size(), want)
	}
}

// Create and delete a directory
func testMkdirRmdir(t *testing.T, plainDir string) {
	dir := plainDir + "dir1"
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Rmdir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Removing a non-empty dir should fail with ENOTEMPTY
	if os.Mkdir(dir, 0777) != nil {
		t.Fatal(err)
	}
	f, err := os.Create(dir + "/file")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = syscall.Rmdir(dir)
	errno := err.(syscall.Errno)
	if errno != syscall.ENOTEMPTY {
		t.Errorf("Should have gotten ENOTEMPTY, go %v", errno)
	}
	if syscall.Unlink(dir+"/file") != nil {
		t.Fatal(err)
	}
	if syscall.Rmdir(dir) != nil {
		t.Fatal(err)
	}

	// We should also be able to remove a directory we do not have permissions to
	// read or write
	err = os.Mkdir(dir, 0000)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Rmdir(dir)
	if err != nil {
		t.Fatal(err)
	}
}

// Create and rename a file
func testRename(t *testing.T, plainDir string) {
	file1 := plainDir + "rename1"
	file2 := plainDir + "rename2"
	err := ioutil.WriteFile(file1, []byte("content"), 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Rename(file1, file2)
	if err != nil {
		t.Fatal(err)
	}
	syscall.Unlink(file2)
}
