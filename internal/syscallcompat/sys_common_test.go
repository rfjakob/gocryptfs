package syscallcompat

import (
	"bytes"
	"os"
	"syscall"
	"testing"
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
