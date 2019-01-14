package syscallcompat

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

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
