// We test two filesystems that have the "HKDF" feature flag in their config file
// set, but the actual file contents and names are encrypted with HKDF disabled.
// This test verifies that the "HKDF" feature flag in the config file takes effect.
package hkdf_sanity

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestBrokenContent(t *testing.T) {
	cDir := "broken_content"
	pDir := test_helpers.TmpDir + "/" + cDir
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test", "-wpanic=false")
	_, err := ioutil.ReadFile(pDir + "/status.txt")
	if err == nil {
		t.Error("this should fail")
	}
	test_helpers.UnmountPanic(pDir)
}

func TestBrokenNames(t *testing.T) {
	cDir := "broken_names"
	pDir := test_helpers.TmpDir + "/" + cDir
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test", "-wpanic=false")
	_, err := os.Stat(pDir + "/status.txt")
	if err == nil {
		t.Error("this should fail")
	}
	test_helpers.UnmountPanic(pDir)
}
