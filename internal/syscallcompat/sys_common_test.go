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
	// Always pass O_NOFOLLOW to avoid this warning:
	// Openat: O_NOFOLLOW missing: flags = 0x0"
	_, err := Openat(tmpDirFd, "testOpenAt", syscall.O_NOFOLLOW, 0)
	if err == nil {
		t.Errorf("should have failed")
	}
	fd, err := os.Create(tmpDir + "/testOpenAt")
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	rawFd, err := Openat(tmpDirFd, "testOpenAt", syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(rawFd)
	if rawFd < 0 {
		t.Fatalf("rawFd=%d", rawFd)
	}
	// Test with absolute path
	rawFd, err = Openat(-1, tmpDir+"/testOpenAt", syscall.O_NOFOLLOW, 0)
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

func TestFchmodatNofollow(t *testing.T) {
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
	err = FchmodatNofollow(dirfd, regular, 0111)
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	syscall.Lstat(tmpDir+"/"+regular, &st)
	st.Mode &= 0777
	if st.Mode != 0111 {
		t.Errorf("wrong mode: %#0o", st.Mode)
	}
	err = FchmodatNofollow(dirfd, regular, 0000)
	if err != nil {
		t.Error(err)
	}
	syscall.Lstat(tmpDir+"/"+regular, &st)
	st.Mode &= 0777
	if st.Mode != 0000 {
		t.Errorf("wrong mode: %#0o", st.Mode)
	}

	// Check what happens on a symlink
	err = FchmodatNofollow(dirfd, symlink, 0333)
	// On Darwin, permissions on symlinks are significant and can be changed. On
	// Linux they are ignored, and FchmodatNofollow rejects attempts to change
	// them.
	if err == nil && runtime.GOOS == "linux" {
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

// We used to have our own wrapper for Symlinkat. The wrapper is gone but the test
// is still useful.
func TestSymlinkat(t *testing.T) {
	err := unix.Symlinkat("/foo/bar/baz", tmpDirFd, "symlink1")
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
	err = unix.Symlinkat("/foo/bar/baz", -1, tmpDir+"/symlink2")
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Lstat(tmpDir+"/symlink2", &st)
	if err != nil {
		t.Fatal(err)
	}
	symlinkCheckMode(t, st)
}

// We used to have our own wrapper for Mkdirat. The wrapper is gone but the test
// is still useful.
func TestMkdirat(t *testing.T) {
	err := unix.Mkdirat(tmpDirFd, "mkdirat", 0700)
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
	err = unix.Mkdirat(-1, tmpDir+"/mkdirat2", 0700)
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

func TestFstatat(t *testing.T) {
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
	err = Fstatat(tmpDirFd, "fstatat", &st, unix.AT_SYMLINK_NOFOLLOW)
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
	err = Fstatat(tmpDirFd, "fstatatSymlink", &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	expectedSize := int64(len(tmpDir + "/fstatat"))
	if st.Size != expectedSize {
		t.Errorf("symlink size: expected=%d, got=%d", expectedSize, st.Size)
	}
}

// BenchmarkLgetxattr benchmarks Lgetxattr. Lgetxattr is very hot as the kernel
// queries security.capabilities for every file access.
func BenchmarkLgetxattr(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Lgetxattr("/", "user.this.attr.does.not.exist")
	}
}
