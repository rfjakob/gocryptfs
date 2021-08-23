package reverse_test

import (
	"io/ioutil"
	"net/url"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestOneFileSystem(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only works on linux")
	}
	// Let's not explode with "TempDir: pattern contains path separator"
	myEscapedName := url.PathEscape(t.Name())
	mnt, err := ioutil.TempDir(test_helpers.TmpDir, myEscapedName)
	if err != nil {
		t.Fatal(err)
	}
	cliArgs := []string{"-reverse", "-zerokey", "-one-file-system"}
	if plaintextnames {
		cliArgs = append(cliArgs, "-plaintextnames")
	} else if deterministic_names {
		cliArgs = append(cliArgs, "-deterministic-names")
	}
	test_helpers.MountOrFatal(t, "/", mnt, cliArgs...)
	defer test_helpers.UnmountErr(mnt)

	// Copied from inomap
	const maxPassthruIno = 1<<48 - 1

	entries, err := ioutil.ReadDir(mnt)
	if err != nil {
		t.Fatal(err)
	}
	mountpoints := []string{}
	for _, e := range entries {
		if !e.IsDir() {
			// We are only interested in directories
			continue
		}
		st := e.Sys().(*syscall.Stat_t)
		// The inode numbers of files with a different device number are remapped
		// to something above maxPassthruIno
		if st.Ino > maxPassthruIno {
			mountpoints = append(mountpoints, e.Name())
		}
	}
	if len(mountpoints) == 0 {
		t.Skip("no mountpoints found, nothing to test")
	}
	for _, m := range mountpoints {
		dir, err := os.Open(mnt + "/" + m)
		if err != nil {
			t.Error(err)
		}
		defer dir.Close()
		e, err := dir.Readdirnames(-1)
		if err != nil {
			t.Error(err)
		}
		expected := 1
		if plaintextnames || deterministic_names {
			expected = 0
		}
		if len(e) != expected {
			t.Errorf("mountpoint %q should have %d entries, actually has: %v", m, expected, e)
		}
	}
	t.Logf("tested %d mountpoints: %v", len(mountpoints), mountpoints)
}
