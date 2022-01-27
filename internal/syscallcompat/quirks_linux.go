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

	// Preallocation on Btrfs is broken ( https://github.com/rfjakob/gocryptfs/issues/395 )
	// and slow ( https://github.com/rfjakob/gocryptfs/issues/63 ).
	//
	// Cast to uint32 avoids compile error on arm: "constant 2435016766 overflows int32"
	if uint32(st.Type) == unix.BTRFS_SUPER_MAGIC {
		logQuirk("Btrfs detected, forcing -noprealloc. See https://github.com/rfjakob/gocryptfs/issues/395 for why.")
		q |= QuirkBrokenFalloc
	}

	if uint32(st.Type) == unix.TMPFS_MAGIC {
		logQuirk("tmpfs detected, no extended attributes except acls will work.")
	}

	return q
}
