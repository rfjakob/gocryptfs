package syscallcompat

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Unix2syscall converts a unix.Stat_t struct to a syscall.Stat_t struct.
func Unix2syscall(u unix.Stat_t) syscall.Stat_t {
	return syscall.Stat_t{
		Dev:       u.Dev,
		Ino:       u.Ino,
		Nlink:     u.Nlink,
		Mode:      u.Mode,
		Uid:       u.Uid,
		Gid:       u.Gid,
		Rdev:      u.Rdev,
		Size:      u.Size,
		Blksize:   u.Blksize,
		Blocks:    u.Blocks,
		Atimespec: syscall.Timespec(u.Atim),
		Mtimespec: syscall.Timespec(u.Mtim),
		Ctimespec: syscall.Timespec(u.Ctim),
	}
}
