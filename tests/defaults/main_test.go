// Tests and benchmarks performed with default settings only.
package defaults

import (
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func TestMain(m *testing.M) {
	test_helpers.ResetTmpDir(true)
	test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, "-zerokey")
	r := m.Run()
	test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
	os.Exit(r)
}
