package syscallcompat

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Unix2syscall converts a unix.Stat_t struct to a syscall.Stat_t struct.
// A direct cast does not work because the padding is named differently in
// unix.Stat_t for some reason ("X__unused" in syscall, "_" in unix).
func Unix2syscall(u unix.Stat_t) syscall.Stat_t {
	return syscall.Stat_t{
		Dev:     u.Dev,
		Ino:     u.Ino,
		Nlink:   u.Nlink,
		Mode:    u.Mode,
		Uid:     u.Uid,
		Gid:     u.Gid,
		Rdev:    u.Rdev,
		Size:    u.Size,
		Blksize: u.Blksize,
		Blocks:  u.Blocks,
		Atim:    syscall.NsecToTimespec(unix.TimespecToNsec(u.Atim)),
		Mtim:    syscall.NsecToTimespec(unix.TimespecToNsec(u.Mtim)),
		Ctim:    syscall.NsecToTimespec(unix.TimespecToNsec(u.Ctim)),
	}
}
