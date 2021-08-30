package syscallcompat

import (
	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

func DetectQuirks(cipherdir string) (q uint64) {
	const (
		// From https://github.com/rfjakob/gocryptfs/issues/585#issuecomment-887370065
		FstypenameExfat = "exfat"
	)

	var st unix.Statfs_t
	err := unix.Statfs(cipherdir, &st)
	if err != nil {
		tlog.Warn.Printf("DetectQuirks: Statfs on %q failed: %v", cipherdir, err)
		return 0
	}

	// Convert null-terminated st.Fstypename int8 array to string
	var buf []byte
	for _, v := range st.Fstypename {
		if v == 0 {
			break
		}
		buf = append(buf, byte(v))
	}
	fstypename := string(buf)
	tlog.Debug.Printf("DetectQuirks: Fstypename=%q\n", fstypename)

	// On MacOS ExFAT, all empty files share inode number 1:
	// https://github.com/rfjakob/gocryptfs/issues/585
	if fstypename == FstypenameExfat {
		logQuirk("ExFAT detected, disabling hard links. See https://github.com/rfjakob/gocryptfs/issues/585 for why.")
		q |= QuirkDuplicateIno1
	}

	return q
}
