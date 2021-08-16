package reverse

import (
	"io/ioutil"
	"net/url"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func doTestOneFileSystem(t *testing.T, plaintextnames bool) {
	// Let's not explode with "TempDir: pattern contains path separator"
	myEscapedName := url.PathEscape(t.Name())
	mnt, err := ioutil.TempDir(test_helpers.TmpDir, myEscapedName)
	if err != nil {
		t.Fatal(err)
	}
	cliArgs := []string{"-reverse", "-zerokey", "-one-file-system"}
	if plaintextnames {
		cliArgs = append(cliArgs, "-plaintextnames")
	}
	test_helpers.MountOrFatal(t, "/", mnt, cliArgs...)
	defer test_helpers.UnmountErr(mnt)

	// Copied from inomap
	const maxPassthruIno = 1<<48 - 1

	entries, err := os.ReadDir(mnt)
	if err != nil {
		t.Fatal(err)
	}
	mountpoints := []string{}
	for _, e := range entries {
		i, err := e.Info()
		if err != nil {
			continue
		}
		if !e.IsDir() {
			// We are only interested in directories
			continue
		}
		st := i.Sys().(*syscall.Stat_t)
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
		e, err := os.ReadDir(mnt + "/" + m)
		if err != nil {
			t.Error(err)
		}
		expected := 1
		if plaintextnames {
			expected = 0
		}
		if len(e) != expected {
			t.Errorf("mountpoint %q does not look empty: %v", m, e)
		}
	}
	t.Logf("tested %d mountpoints: %v", len(mountpoints), mountpoints)
}

func TestOneFileSystem(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only works on linux")
	}
	t.Run("normal", func(t *testing.T) { doTestOneFileSystem(t, false) })
	t.Run("plaintextnames", func(t *testing.T) { doTestOneFileSystem(t, true) })
}
