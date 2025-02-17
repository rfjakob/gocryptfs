package root_test

import (
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestMain(m *testing.M) {
	test_helpers.ResetTmpDir(true)
	os.Chmod(test_helpers.DefaultCipherDir, 0755)
	test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, "-zerokey", "-allow_other")
	r := m.Run()
	test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
	os.RemoveAll(test_helpers.TmpDir)
	os.Exit(r)
}
