package fusefrontend

import (
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	quirkBrokenFalloc = uint64(1 << iota)
	quirkDuplicateIno1
)

func detectQuirks(cipherdir string) (q uint64) {
	const (
		// From Linux' man statfs
		BTRFS_SUPER_MAGIC = 0x9123683e

		// From https://github.com/rfjakob/gocryptfs/issues/585#issuecomment-887370065
		DARWIN_EXFAT_MAGIC = 35
	)

	var st unix.Statfs_t
	err := unix.Statfs(cipherdir, &st)
	if err != nil {
		tlog.Warn.Printf("detectQuirks: Statfs on %q failed: %v", cipherdir, err)
		return 0
	}

	logQuirk := func(s string) {
		tlog.Info.Printf(tlog.ColorYellow + "detectQuirks: " + s + tlog.ColorReset)
	}

	// Preallocation on Btrfs is broken ( https://github.com/rfjakob/gocryptfs/issues/395 )
	// and slow ( https://github.com/rfjakob/gocryptfs/issues/63 ).
	//
	// Cast to uint32 avoids compile error on arm: "constant 2435016766 overflows int32"
	if uint32(st.Type) == BTRFS_SUPER_MAGIC {
		logQuirk("Btrfs detected, forcing -noprealloc. See https://github.com/rfjakob/gocryptfs/issues/395 for why.")
		q |= quirkBrokenFalloc
	}
	// On MacOS ExFAT, all empty files share inode number 1:
	// https://github.com/rfjakob/gocryptfs/issues/585
	if runtime.GOOS == "darwin" && st.Type == DARWIN_EXFAT_MAGIC {
		logQuirk("ExFAT detected, disabling hard links. See https://github.com/rfjakob/gocryptfs/issues/585 for why.")
		q |= quirkDuplicateIno1
	}

	return q
}
