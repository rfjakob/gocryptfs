package reverse_test

import (
	"io/ioutil"
	"net/url"
	"os"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestForceOwner(t *testing.T) {
	// Let's not explode with "TempDir: pattern contains path separator"
	myEscapedName := url.PathEscape(t.Name())
	mnt, err := ioutil.TempDir(test_helpers.TmpDir, myEscapedName)
	if err != nil {
		t.Fatal(err)
	}
	cliArgs := []string{"-reverse", "-zerokey", "-force_owner=1234:1234"}
	if plaintextnames {
		cliArgs = append(cliArgs, "-plaintextnames")
	} else if deterministic_names {
		cliArgs = append(cliArgs, "-deterministic-names")
	}
	test_helpers.MountOrFatal(t, "/", mnt, cliArgs...)
	defer test_helpers.UnmountErr(mnt)

	entries, err := os.ReadDir(mnt)
	if err != nil {
		t.Fatal(err)
	}

	// Check the mountpoint and everything inside it
	toCheck := []string{mnt}
	for _, e := range entries {
		toCheck = append(toCheck, mnt+"/"+e.Name())
	}

	var st syscall.Stat_t
	for _, path := range toCheck {
		if err := syscall.Lstat(path, &st); err != nil {
			t.Fatal(err)
		}
		if st.Uid != 1234 || st.Gid != 1234 {
			t.Errorf("file %q: uid or gid != 1234: %#v", path, st)
		}
	}

}
