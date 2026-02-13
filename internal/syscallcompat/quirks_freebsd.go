package syscallcompat

import (
	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// DetectQuirks decides if there are known quirks on the backing filesystem
// that need to be workarounded.
//
// Tested by tests/root_test.TestBtrfsQuirks
func DetectQuirks(cipherdir string) (q uint64) {
	var st unix.Statfs_t
	err := unix.Statfs(cipherdir, &st)
	if err != nil {
		tlog.Warn.Printf("DetectQuirks: Statfs on %q failed: %v", cipherdir, err)
		return 0
	}

	return q
}
