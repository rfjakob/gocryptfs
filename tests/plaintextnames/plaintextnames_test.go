package plaintextnames

// integration tests that target plaintextnames specifically

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/configfile"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
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
	_, cf, err := configfile.Load(cDir+"/gocryptfs.conf", testPw)
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
