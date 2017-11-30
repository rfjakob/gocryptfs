package syscallcompat

import (
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

var tmpDir string
var tmpDirFd int

func TestMain(m *testing.M) {
	origWd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	parent := "/tmp/gocryptfs-test-parent"
	err = os.MkdirAll(parent, 0700)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	tmpDir, err = ioutil.TempDir(parent, "syscallcompat")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dirf, err := os.Open(tmpDir)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer dirf.Close()
	tmpDirFd = int(dirf.Fd())
	// Run the tests
	r := m.Run()
	// Check that we are in the same directory again (the emulated syscalls
	// use Fchdir a lot)
	cwd, _ := os.Getwd()
	if cwd != origWd {
		fmt.Printf("working dir has changed from %q to %q", origWd, cwd)
		os.Exit(1)
	}
	os.Exit(r)
}

func TestEmulateOpenat(t *testing.T) {
	_, err := emulateOpenat(tmpDirFd, "testOpenAt", 0, 0)
	if err == nil {
		t.Errorf("should have failed")
	}
	fd, err := os.Create(tmpDir + "/testOpenAt")
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	rawFd, err := emulateOpenat(tmpDirFd, "testOpenAt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(rawFd)
	if rawFd < 0 {
		t.Fatalf("rawFd=%d", rawFd)
	}
}

func TestEmulateRenameat(t *testing.T) {
	os.Mkdir(tmpDir+"/dir1", 0700)
	dir1, err := os.Open(tmpDir + "/dir1")
	if err != nil {
		t.Fatal(err)
	}
	defer dir1.Close()
	os.Mkdir(tmpDir+"/dir2", 0700)
	dir2, err := os.Open(tmpDir + "/dir2")
	if err != nil {
		t.Fatal(err)
	}
	defer dir2.Close()
	fd, err := os.Create(tmpDir + "/dir1/f1")
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	err = emulateRenameat(int(dir1.Fd()), "f1", int(dir2.Fd()), "f2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/dir2/f2")
	if err != nil {
		t.Fatal(err)
	}
}

func TestEmulateUnlinkat(t *testing.T) {
	os.Mkdir(tmpDir+"/unlink1", 0700)
	dirfd, err := os.Open(tmpDir + "/unlink1")
	if err != nil {
		t.Fatal(err)
	}
	defer dirfd.Close()
	// Try to delete file
	fd, err := os.Create(tmpDir + "/unlink1/f1")
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	err = emulateUnlinkat(int(dirfd.Fd()), "f1", 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/unlink1/f1")
	if err == nil {
		t.Fatalf("file not deleted!")
	}
	// Try to delete dir
	err = os.Mkdir(tmpDir+"/unlink1/d1", 0700)
	if err != nil {
		t.Fatal(err)
	}
	err = emulateUnlinkat(int(dirfd.Fd()), "d1", 0)
	if err == nil {
		t.Fatalf("this should fail due to missing AT_REMOVEDIR flag")
	}
	err = emulateUnlinkat(int(dirfd.Fd()), "d1", unix.AT_REMOVEDIR)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/unlink1/d1")
	if err == nil {
		t.Fatalf("dir not deleted!")
	}
}

func TestEmulateMknodat(t *testing.T) {
	err := emulateMknodat(tmpDirFd, "fifo1", unix.S_IFIFO, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/fifo1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestEmulateFchmodat(t *testing.T) {
	fd, err := os.Create(tmpDir + "/chmod")
	if err != nil {
		t.Fatal(err)
	}
	err = fd.Chmod(0654)
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	// Chmod a normal file
	err = emulateFchmodat(tmpDirFd, "chmod", 0600, 0)
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	err = syscall.Lstat(tmpDir+"/chmod", &st)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode != 0100600 {
		t.Fatalf("Wrong mode: have %o, want %o", st.Mode, 0100600)
	}
	// Chmod a symlink (original file should not change)
	err = os.Symlink(tmpDir+"/chmod", tmpDir+"/chmodSymlink")
	if err != nil {
		t.Fatal(err)
	}
	err = emulateFchmodat(tmpDirFd, "chmodSymlink", 0123, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Lstat(tmpDir+"/chmod", &st)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode != 0100600 {
		t.Fatalf("Wrong mode: have %o, want %o", st.Mode, 0100600)
	}
}

func TestEmulateFchownat(t *testing.T) {
	t.Skipf("TODO")
}

func TestEmulateSymlinkat(t *testing.T) {
	err := emulateSymlinkat("/foo/bar/baz", tmpDirFd, "symlink1")
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	err = syscall.Lstat(tmpDir+"/symlink1", &st)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode != 0120777 {
		t.Fatalf("Wrong mode, have %o, want 0120777", st.Mode)
	}
}

func TestEmulateMkdirat(t *testing.T) {
	err := emulateMkdirat(tmpDirFd, "mkdirat", 0100)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(tmpDir + "/mkdirat")
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("mkdirat did not create a directory")
	}
}
