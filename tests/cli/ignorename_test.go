package cli

import (
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestIgnorename checks that undecryptable names matching -ignorename are
// hidden without a warning (the test mount runs with -wpanic, so a warning
// would kill it) and are not reported by -fsck, while valid files stay
// visible.
func TestIgnorename(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	ignoreArgs := []string{"-ignorename=.*", "-ignorename=*.pgp"}

	// Files that are not part of the filesystem, as when the cipherdir
	// is a git working tree
	if err := os.Mkdir(dir+"/.git", 0700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".gitignore", "creds.pgp"} {
		if err := os.WriteFile(dir+"/"+f, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	test_helpers.MountOrFatal(t, dir, mnt, append([]string{"-extpass=echo test"}, ignoreArgs...)...)
	if err := os.WriteFile(mnt+"/file", []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mnt+"/subdir", 0700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(mnt)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "file,subdir" {
		t.Errorf("wrong directory listing: %v", names)
	}
	test_helpers.UnmountPanic(mnt)

	fsck := func(extraArgs ...string) (string, int) {
		args := append([]string{"-fsck", "-extpass", "echo test"}, extraArgs...)
		args = append(args, dir)
		out, err := exec.Command(test_helpers.GocryptfsBinary, args...).CombinedOutput()
		return string(out), test_helpers.ExtractCmdExitCode(err)
	}
	if out, code := fsck(ignoreArgs...); code != 0 {
		t.Errorf("-fsck with -ignorename: exit code %d, want 0. Output:\n%s", code, out)
	}
	if out, code := fsck(); code != exitcodes.FsckErrors {
		t.Errorf("-fsck without -ignorename: exit code %d, want %d. Output:\n%s", code, exitcodes.FsckErrors, out)
	}
}

// TestIgnorenameInvalidPattern checks that a malformed glob is rejected.
func TestIgnorenameInvalidPattern(t *testing.T) {
	dir := test_helpers.InitFS(t)
	err := exec.Command(test_helpers.GocryptfsBinary, "-extpass", "echo test", "-ignorename=[", dir, dir+".mnt").Run()
	if code := test_helpers.ExtractCmdExitCode(err); code != exitcodes.Usage {
		t.Errorf("wrong exit code, have=%d want=%d", code, exitcodes.Usage)
	}
}
