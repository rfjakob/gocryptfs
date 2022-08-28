package cli

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// Create & test fs with -longnamemax=100
func TestLongnamemax100(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-longnamemax", "100")
	pDir := cDir + ".mnt"

	// Check config file sanity
	_, c, err := configfile.LoadAndDecrypt(cDir+"/"+configfile.ConfDefaultName, testPw)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if !c.IsFeatureFlagSet(configfile.FlagLongNameMax) {
		t.Error("FlagLongNameMax should be on")
	}
	if c.LongNameMax != 100 {
		t.Errorf("LongNameMax=%d, want 100", c.LongNameMax)
	}

	// Check that it takes effect
	test_helpers.MountOrExit(cDir, pDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(pDir)

	for l := 1; l <= 255; l++ {
		path := pDir + "/" + strings.Repeat("x", l)
		if err := ioutil.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		matches, err := filepath.Glob(cDir + "/gocryptfs.longname.*")
		if err != nil {
			t.Fatal(err)
		}
		err = syscall.Unlink(path)
		if err != nil {
			t.Fatal(err)
		}
		// As determined experimentally, a name of length >= 64 causes a longname
		// to be created.
		if l <= 63 && len(matches) != 0 {
			t.Errorf("l=%d: should not see a longname yet", l)
		}
		if l >= 64 && len(matches) != 2 {
			t.Errorf("l=%d: should see a longname now", l)
		}
	}
}

// Create & test fs with -reverse -longnamemax=100
func TestLongnamemax100Reverse(t *testing.T) {
	backingDir := test_helpers.InitFS(t, "-reverse", "-longnamemax", "100")
	mntDir := backingDir + ".mnt"

	// Check config file sanity
	_, c, err := configfile.LoadAndDecrypt(backingDir+"/"+configfile.ConfReverseName, testPw)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if !c.IsFeatureFlagSet(configfile.FlagLongNameMax) {
		t.Error("FlagLongNameMax should be on")
	}
	if c.LongNameMax != 100 {
		t.Errorf("LongNameMax=%d, want 100", c.LongNameMax)
	}

	// Check that it takes effect
	test_helpers.MountOrExit(backingDir, mntDir, "-reverse", "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	for l := 1; l <= 255; l++ {
		path := backingDir + "/" + strings.Repeat("x", l)
		if err := ioutil.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		matches, err := filepath.Glob(mntDir + "/gocryptfs.longname.*")
		if err != nil {
			t.Fatal(err)
		}
		err = syscall.Unlink(path)
		if err != nil {
			t.Fatal(err)
		}
		// As determined experimentally, a name of length >= 64 causes a longname
		// to be created.
		if l <= 63 && len(matches) != 0 {
			t.Errorf("l=%d: should not see a longname yet", l)
		}
		if l >= 64 && len(matches) != 2 {
			t.Errorf("l=%d: should see a longname now", l)
		}
	}
}
