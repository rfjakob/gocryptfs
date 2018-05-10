package fsck

import (
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/pkg/xattr"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func dec64(in string) (out []byte) {
	out, err := base64.RawURLEncoding.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return out
}

func TestBrokenFsV14(t *testing.T) {
	// git does not save extended attributes, so we apply them here.
	// xattr_good
	xattr.Set("broken_fs_v1.4/6nGs4Ugr3EAHd0KzkyLZ-Q",
		"user.gocryptfs.0a5e7yWl0SGUGeWB0Sy2Kg",
		dec64("hxnZvXSkDicfwVS9w4r1yYkFF61Qou6NaL-VhObYEdu6kuM"))
	// xattr_corrupt_name
	xattr.Set("broken_fs_v1.4/CMyUifVTjW5fsgXonWBT_RDkvLkdGrLttkZ45T3Oi3A",
		"user.gocryptfs.0a5e7yWl0SGUGeWB0Sy2K0",
		dec64("QHUMDTgbnl8Sv_A2dFQic_G2vN4_gmDna3651JAhF7OZ-YI"))
	// xattr_corrupt_value
	xattr.Set("broken_fs_v1.4/b00sbnGXGToadr01GHZaYQn8tjyRhe1OXNBZoQtMlcQ",
		"user.gocryptfs.0a5e7yWl0SGUGeWB0Sy2Kg",
		dec64("A0hvCePeKpL8bCpijhDKtf7cIijXYQsPnEbNJ84M2ONW0dd"))

	cmd := exec.Command(test_helpers.GocryptfsBinary, "-fsck", "-extpass", "echo test", "broken_fs_v1.4")
	outBin, err := cmd.CombinedOutput()
	out := string(outBin)
	t.Log(out)
	code := test_helpers.ExtractCmdExitCode(err)
	if code != exitcodes.FsckErrors {
		t.Errorf("wrong exit code, have=%d want=%d", code, exitcodes.FsckErrors)
	}
}

func TestExampleFses(t *testing.T) {
	dirfd, err := os.Open("../example_filesystems")
	if err != nil {
		t.Fatal(err)
	}
	var fsNames []string
	entries, err := dirfd.Readdir(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.Contains(e.Name(), "reverse") {
			continue
		}
		if e.Name() == "content" {
			continue
		}
		fsNames = append(fsNames, e.Name())
	}
	for _, n := range fsNames {
		path := "../example_filesystems/" + n
		cmd := exec.Command(test_helpers.GocryptfsBinary, "-fsck", "-extpass", "echo test", path)
		outBin, err := cmd.CombinedOutput()
		out := string(outBin)
		code := test_helpers.ExtractCmdExitCode(err)
		if code == exitcodes.DeprecatedFS {
			continue
		}
		if code != 0 {
			t.Log(out)
			t.Errorf("fsck returned code %d but fs should be clean", code)
		}
	}
}
