package zerodiriv

// integration tests that target zerodiriv specifically

import (
	"bytes"
	"path/filepath"
	"io/ioutil"
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

var cDir string
var pDir string

var testPw = []byte("test")

// Create and mount "-zerodiriv" fs
func TestMain(m *testing.M) {
	cDir = test_helpers.InitFS(nil, "-zerodiriv")
	pDir = cDir + ".mnt"
	test_helpers.MountOrExit(cDir, pDir, "-zerodiriv", "-extpass", "echo test")
	r := m.Run()
	test_helpers.UnmountPanic(pDir)
	os.Exit(r)
}

// diriv should be all-zero on newly created dirs
func TestZeroDirIV(t *testing.T) {
	// Create /dir1, move it and create it again
	var dirPath = pDir+"/dir1"
	var err = os.Mkdir(dirPath, 0777)
	if err != nil {
		t.Error(err)
	}
	err = os.Rename(dirPath, dirPath + ".bak")
	if err != nil {
		t.Error(err)
	}
	err = os.Mkdir(dirPath, 0777)
	if err != nil {
		t.Error(err)
	}

	var matches []string
	matches, err = filepath.Glob(cDir+"/*/gocryptfs.diriv")
	if err != nil {
		t.Error(err)
	}

	// The contents of the both diriv files must be the same
	var diriv0 []byte
	diriv0, err = ioutil.ReadFile(matches[0])
	if err != nil {
		t.Error(err)
	}
	var diriv1 []byte
	diriv1, err = ioutil.ReadFile(matches[1])
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(diriv0, diriv1) {
		t.Errorf("both dirivs should have the same value")
	}
	// And equal to zero
	zerodiriv := make([]byte, len(diriv0))
	if !bytes.Equal(diriv0, zerodiriv) {
		t.Errorf("both dirivs should be all-zero")
	}
}

// root diriv should be all-zero
func TestZeroRootDirIV(t *testing.T) {
	// The contents of the diriv file must be zero
	diriv, err := ioutil.ReadFile(cDir+"/gocryptfs.diriv")
	if err != nil {
		t.Error(err)
	}
	zerodiriv := make([]byte, len(diriv))
	if !bytes.Equal(diriv, zerodiriv) {
		t.Errorf("root diriv should be all-zero")
	}
}
