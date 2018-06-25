package trezor

// Test operations with "-trezor".
// See also the "cli" package - the tests there are very similar.

import (
	"os/exec"
	"runtime"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func isTrezorConnected() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	c := exec.Command("lsusb", "-d", "534c:0001")
	err := c.Run()
	if err != nil {
		return false
	}
	return true
}

// Test -init with -trezor
func TestInitTrezor(t *testing.T) {
	if !isTrezorConnected() {
		t.Skip("No Trezor device connected")
	}
	t.Log("Trying gocryptfs -init -trezor ...")
	//                                        vvvvvvvvvvvvv disable -extpass
	dir := test_helpers.InitFS(t, "-trezor", "-extpass", "")
	// The freshly created config file should have the Trezor feature flag set.
	_, c, err := configfile.Load(dir+"/"+configfile.ConfDefaultName, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsFeatureFlagSet(configfile.FlagTrezor) {
		t.Error("Trezor flag should be set but is not")
	}
	if len(c.TrezorPayload) != 32 {
		t.Errorf("TrezorPayload has wrong length: %d", len(c.TrezorPayload))
	}
}

// Test using -trezor together with -extpass. Should fail with code 1 (usage error).
func TestTrezorExtpass(t *testing.T) {
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-init", "-trezor", "-extpass", "foo", "/tmp")
	err := cmd.Run()
	exitCode := test_helpers.ExtractCmdExitCode(err)
	if exitCode != exitcodes.Usage {
		t.Errorf("wrong exit code: want %d, have %d", exitcodes.Usage, exitCode)
	}
}
