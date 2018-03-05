package syscallcompat

import (
	"os"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

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
	// Test with absolute path
	rawFd, err = emulateOpenat(-1, tmpDir+"/testOpenAt", 0, 0)
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
	// Test with absolute path
	err = emulateRenameat(-1, tmpDir+"/dir2/f2", -1, tmpDir+"/dir2/f1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/dir2/f1")
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
	// Test with absolute path
	err = os.Mkdir(tmpDir+"/unlink1/d1", 0700)
	if err != nil {
		t.Fatal(err)
	}
	err = emulateUnlinkat(-1, tmpDir+"/unlink1/d1", unix.AT_REMOVEDIR)
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
	// Test with absolute path
	err = emulateMknodat(-1, tmpDir+"/fifo2", unix.S_IFIFO, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/fifo2")
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
	// Test with absolute path
	err = emulateFchmodat(-1, tmpDir+"/chmod", 0400, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Lstat(tmpDir+"/chmod", &st)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode != 0100400 {
		t.Fatalf("Wrong mode: have %o, want %o", st.Mode, 0100400)
	}
}

func TestEmulateFchownat(t *testing.T) {
	t.Skipf("TODO")
}

// symlinkCheckMode looks if the mode bits in "st" say that this is a symlink.
// Calls t.Fatal() if not.
func symlinkCheckMode(t *testing.T, st syscall.Stat_t) {
	if runtime.GOOS == "darwin" {
		// On MacOS, symlinks don't carry their own permissions, so
		// only check the file type.
		if st.Mode&syscall.S_IFMT != syscall.S_IFLNK {
			t.Fatalf("This is not a symlink: mode = 0%o", st.Mode)
		}
		return
	}
	if st.Mode != 0120777 {
		t.Fatalf("Wrong mode, have 0%o, want 0120777", st.Mode)
	}
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
	symlinkCheckMode(t, st)
	// Test with absolute path
	err = emulateSymlinkat("/foo/bar/baz", -1, tmpDir+"/symlink2")
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Lstat(tmpDir+"/symlink2", &st)
	if err != nil {
		t.Fatal(err)
	}
	symlinkCheckMode(t, st)
}

func TestEmulateMkdirat(t *testing.T) {
	err := emulateMkdirat(tmpDirFd, "mkdirat", 0700)
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
	// Test with absolute path
	err = emulateMkdirat(-1, tmpDir+"/mkdirat2", 0700)
	if err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(tmpDir + "/mkdirat2")
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("mkdirat did not create a directory")
	}
}

func TestEmulateFstatat(t *testing.T) {
	var st unix.Stat_t
	// stat a normal file (size 3)
	f, err := os.Create(tmpDir + "/fstatat")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = emulateFstatat(tmpDirFd, "fstatat", &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size != 3 {
		t.Errorf("wrong file size: %d", st.Size)
	}
	// stat a symlink and check that the size matches the length of the
	// symlink target. This proves that we have stat'ed the symlink itself.
	err = os.Symlink(tmpDir+"/fstatat", tmpDir+"/fstatatSymlink")
	if err != nil {
		t.Fatal(err)
	}
	err = emulateFstatat(tmpDirFd, "fstatatSymlink", &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	expectedSize := int64(len(tmpDir + "/fstatat"))
	if st.Size != expectedSize {
		t.Errorf("symlink size: expected=%d, got=%d", expectedSize, st.Size)
	}
}
