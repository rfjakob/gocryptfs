package fsck

import (
	"os/exec"
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
