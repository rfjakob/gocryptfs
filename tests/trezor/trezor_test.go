package trezor

// Test operations with "-trezor".
// See also the "cli" package - the tests there are very similar.

import (
	"os/exec"
	"runtime"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/configfile"

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
	_, c, err := configfile.LoadConfFile(dir+"/"+configfile.ConfDefaultName, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsFeatureFlagSet(configfile.FlagTrezor) {
		t.Error("Trezor flag should be set but is not")
	}
}
