package fsck

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func TestBrokenFsV14(t *testing.T) {
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
