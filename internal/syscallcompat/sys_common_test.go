package syscallcompat

import (
	"bytes"
	"os"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadlinkat(t *testing.T) {
	for _, targetLen := range []int{100, 500, 4000} {
		target := string(bytes.Repeat([]byte("x"), targetLen))
		err := syscall.Symlink(target, tmpDir+"/readlinkat")
		if err != nil {
			if targetLen > 1000 {
				// Symlinks longer than 1024 (?) bytes are not supported on
				// MacOS and XFS
				t.Logf("skipping targetLen=%d: %v", targetLen, err)
				continue
			}
			t.Fatalf("targetLen=%d: %v", targetLen, err)
		}
		target2, err := Readlinkat(tmpDirFd, "readlinkat")
		if err != nil {
			t.Fatal(err)
		}
		if target != target2 {
			t.Errorf("target=%q != target2=%q", target, target2)
		}
		err = syscall.Unlink(tmpDir + "/readlinkat")
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenat(t *testing.T) {
	_, err := Openat(tmpDirFd, "testOpenAt", 0, 0)
	if err == nil {
		t.Errorf("should have failed")
	}
	fd, err := os.Create(tmpDir + "/testOpenAt")
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	rawFd, err := Openat(tmpDirFd, "testOpenAt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(rawFd)
	if rawFd < 0 {
		t.Fatalf("rawFd=%d", rawFd)
	}
	// Test with absolute path
	rawFd, err = Openat(-1, tmpDir+"/testOpenAt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(rawFd)
	if rawFd < 0 {
		t.Fatalf("rawFd=%d", rawFd)
	}
}

func TestRenameat(t *testing.T) {
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
	err = Renameat(int(dir1.Fd()), "f1", int(dir2.Fd()), "f2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/dir2/f2")
	if err != nil {
		t.Fatal(err)
	}
	// Test with absolute path
	err = Renameat(-1, tmpDir+"/dir2/f2", -1, tmpDir+"/dir2/f1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/dir2/f1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnlinkat(t *testing.T) {
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
	err = Unlinkat(int(dirfd.Fd()), "f1", 0)
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
	err = Unlinkat(int(dirfd.Fd()), "d1", 0)
	if err == nil {
		t.Fatalf("this should fail due to missing AT_REMOVEDIR flag")
	}
	err = Unlinkat(int(dirfd.Fd()), "d1", unix.AT_REMOVEDIR)
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
	err = Unlinkat(-1, tmpDir+"/unlink1/d1", unix.AT_REMOVEDIR)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/unlink1/d1")
	if err == nil {
		t.Fatalf("dir not deleted!")
	}
}

func TestFchmodat(t *testing.T) {
	regular := "TestFchmodat_Regular"
	f, err := os.OpenFile(tmpDir+"/"+regular, os.O_CREATE|os.O_WRONLY, 0000)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	symlink := "TestFchmodat_Symlink"
	err = syscall.Symlink(regular, tmpDir+"/"+symlink)
	if err != nil {
		t.Fatal(err)
	}
	dirfd, err := syscall.Open(tmpDir, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(dirfd)

	// Check that chmod on a regular file works ok
	err = Fchmodat(dirfd, regular, 0111, 0)
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	syscall.Lstat(tmpDir+"/"+regular, &st)
	st.Mode &= 0777
	if st.Mode != 0111 {
		t.Errorf("wrong mode: %#0o", st.Mode)
	}
	err = Fchmodat(dirfd, regular, 0000, 0)
	if err != nil {
		t.Error(err)
	}
	syscall.Lstat(tmpDir+"/"+regular, &st)
	st.Mode &= 0777
	if st.Mode != 0000 {
		t.Errorf("wrong mode: %#0o", st.Mode)
	}

	// Check what happens on a symlink
	err = Fchmodat(dirfd, symlink, 0333, 0)
	if err == nil {
		syscall.Lstat(tmpDir+"/"+symlink, &st)
		st.Mode &= 0777
		t.Errorf("chmod on symlink should have failed, but did not. New mode=%#0o", st.Mode)
	}
	syscall.Lstat(tmpDir+"/"+regular, &st)
	st.Mode &= 0777
	if st.Mode != 0000 {
		t.Errorf("chmod on symlink affected symlink target: New mode=%#0o", st.Mode)
	}
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

func TestSymlinkat(t *testing.T) {
	err := Symlinkat("/foo/bar/baz", tmpDirFd, "symlink1")
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
	err = Symlinkat("/foo/bar/baz", -1, tmpDir+"/symlink2")
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Lstat(tmpDir+"/symlink2", &st)
	if err != nil {
		t.Fatal(err)
	}
	symlinkCheckMode(t, st)
}
