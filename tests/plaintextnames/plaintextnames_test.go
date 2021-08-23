package plaintextnames

// integration tests that target plaintextnames specifically

import (
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

var cDir string
var pDir string

var testPw = []byte("test")

// Create and mount "-plaintextnames" fs
func TestMain(m *testing.M) {
	cDir = test_helpers.InitFS(nil, "-plaintextnames")
	pDir = cDir + ".mnt"
	test_helpers.MountOrExit(cDir, pDir, "-extpass", "echo test")
	r := m.Run()
	test_helpers.UnmountPanic(pDir)
	os.Exit(r)
}

// Only the PlaintextNames feature flag should be set
func TestFlags(t *testing.T) {
	_, cf, err := configfile.LoadAndDecrypt(cDir+"/gocryptfs.conf", testPw)
	if err != nil {
		t.Fatal(err)
	}
	if !cf.IsFeatureFlagSet(configfile.FlagPlaintextNames) {
		t.Error("PlaintextNames flag should be set but isn't")
	}
	if cf.IsFeatureFlagSet(configfile.FlagEMENames) || cf.IsFeatureFlagSet(configfile.FlagDirIV) {
		t.Error("FlagEMENames and FlagDirIV should be not set")
	}
}

// gocryptfs.diriv should NOT be created
func TestDirIV(t *testing.T) {
	_, err := os.Stat(cDir + "/gocryptfs.diriv")
	if err == nil {
		t.Errorf("gocryptfs.diriv should not be created in the top directory")
	}
	err = os.Mkdir(pDir+"/dir1", 0777)
	if err != nil {
		t.Error(err)
	}
	_, err = os.Stat(pDir + "/dir1/gocryptfs.diriv")
	if err == nil {
		t.Errorf("gocryptfs.diriv should not be created in a subdirectory")
	}
}

// With "-plaintextnames", the name "/gocryptfs.conf" is reserved, but everything
// else should work.
func TestFiltered(t *testing.T) {
	filteredFile := pDir + "/gocryptfs.conf"
	err := ioutil.WriteFile(filteredFile, []byte("foo"), 0777)
	if err == nil {
		t.Errorf("should have failed but didn't")
	}
	err = os.Remove(filteredFile)
	if err == nil {
		t.Errorf("should have failed but didn't")
	}
	err = ioutil.WriteFile(pDir+"/gocryptfs.diriv", []byte("foo"), 0777)
	if err != nil {
		t.Error(err)
	}
	subDir, err := ioutil.TempDir(pDir, "")
	if err != nil {
		t.Fatal(err)
	}
	fd, err := os.Create(subDir + "/gocryptfs.conf")
	if err != nil {
		t.Error(err)
	} else {
		fd.Close()
	}
}

// TestInoReuseEvil makes it appear that a directory and a file share the
// same inode number.
// Only works on filesystems that recycle inode numbers (ext4 does),
// and then the test causes a hang with these messages:
//
//		go-fuse: blocked for 5 seconds waiting for FORGET on i4329366
//		go-fuse: blocked for 11 seconds waiting for FORGET on i4329366
//		go-fuse: blocked for 17 seconds waiting for FORGET on i4329366
//		[...]
//
// The test runs with -plaintextnames because that makes it easier to manipulate
// cipherdir directly.
func TestInoReuseEvil(t *testing.T) {
	for i := 0; i < 2; i++ {
		n := fmt.Sprintf("%s.%d", t.Name(), i)
		pPath := pDir + "/" + n
		cPath := cDir + "/" + n
		if err := syscall.Mkdir(pPath, 0700); err != nil {
			t.Fatal(err)
		}
		var st syscall.Stat_t
		syscall.Stat(pPath, &st)
		t.Logf("dir  ino = %d", st.Ino)
		// delete the dir "behind our back"
		if err := syscall.Rmdir(cPath); err != nil {
			t.Fatal(err)
		}
		// create a new file that will likely get the same inode number
		pPath2 := pPath + "2"
		fd, err := syscall.Creat(pPath2, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(fd)
		syscall.Fstat(fd, &st)
		t.Logf("file ino = %d", st.Ino)
	}
}
