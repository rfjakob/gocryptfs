package deterministic_names

// integration tests that target "-deterministic-names" specifically

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

var cDir string
var pDir string

var testPw = []byte("test")

// Create and mount "-deterministic-names" fs
func TestMain(m *testing.M) {
	cDir = test_helpers.InitFS(nil, "-deterministic-names")
	// Check config file sanity
	_, c, err := configfile.LoadAndDecrypt(cDir+"/"+configfile.ConfDefaultName, testPw)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if c.IsFeatureFlagSet(configfile.FlagDirIV) {
		fmt.Println("DirIV flag should be off")
		os.Exit(1)
	}
	pDir = cDir + ".mnt"
	test_helpers.MountOrExit(cDir, pDir, "-extpass", "echo test")
	r := m.Run()
	test_helpers.UnmountPanic(pDir)
	os.Exit(r)
}

// TestDeterministicNames checks that a file with the same plaintext name
// always encrypts to the same ciphertext name
func TestDeterministicNames(t *testing.T) {
	// "foo" should encrypt to the same name in both directories
	if err := os.MkdirAll(pDir+"/x/foo", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pDir+"/y/foo", 0700); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(cDir + "/*/*")
	if err != nil || len(matches) != 2 {
		t.Fatal(matches, err)
	}
	if filepath.Base(matches[0]) != filepath.Base(matches[1]) {
		t.Error(matches)
	}
	fooEncrypted := filepath.Base(matches[0])

	// "foo" should also encrypt to the same name in the root directory
	if err := os.Mkdir(pDir+"/foo", 0700); err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(cDir + "/" + fooEncrypted)
	if err != nil {
		t.Error(err)
	}

	// Replace directory with file
	if err := os.RemoveAll(pDir + "/foo"); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(pDir+"/foo", nil, 0700); err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(cDir + "/" + fooEncrypted)
	if err != nil {
		t.Error(err)
	}

	// Rename back and forth, name should stay the same
	if err := os.Rename(pDir+"/foo", pDir+"/foo.tmp"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pDir+"/foo.tmp", pDir+"/foo"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cDir + "/" + fooEncrypted); err != nil {
		t.Error(err)
	}
}
