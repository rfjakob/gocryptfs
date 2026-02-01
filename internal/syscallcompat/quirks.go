package syscallcompat

import (
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// QuirkBtrfsBrokenFalloc means the falloc is broken.
	// Preallocation on Btrfs is broken ( https://github.com/rfjakob/gocryptfs/issues/395 )
	// and slow ( https://github.com/rfjakob/gocryptfs/issues/63 ).
	QuirkBtrfsBrokenFalloc = uint64(1 << iota)
	// QuirkDuplicateIno1 means that we have duplicate inode numbers.
	// On MacOS ExFAT, all empty files share inode number 1:
	// https://github.com/rfjakob/gocryptfs/issues/585
	QuirkDuplicateIno1
)

// LogQuirk prints a yellow message about a detected quirk.
func LogQuirk(s string) {
	tlog.Info.Println(tlog.ColorYellow + "DetectQuirks: " + s + tlog.ColorReset)
}
