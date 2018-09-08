// Package syscallcompat wraps Linux-specific syscalls.
package syscallcompat

import (
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	_FALLOC_FL_KEEP_SIZE = 0x01

	// O_DIRECT means oncached I/O on Linux. No direct equivalent on MacOS and defined
	// to zero there.
	O_DIRECT = syscall.O_DIRECT

	// O_PATH is only defined on Linux
	O_PATH = unix.O_PATH
)

var preallocWarn sync.Once

// EnospcPrealloc preallocates ciphertext space without changing the file
// size. This guarantees that we don't run out of space while writing a
// ciphertext block (that would corrupt the block).
func EnospcPrealloc(fd int, off int64, len int64) (err error) {
	for {
		err = syscall.Fallocate(fd, _FALLOC_FL_KEEP_SIZE, off, len)
		if err == syscall.EINTR {
			// fallocate, like many syscalls, can return EINTR. This is not an
			// error and just signifies that the operation was interrupted by a
			// signal and we should try again.
			continue
		}
		if err == syscall.EOPNOTSUPP {
			// ZFS and ext3 do not support fallocate. Warn but continue anyway.
			// https://github.com/rfjakob/gocryptfs/issues/22
			preallocWarn.Do(func() {
				tlog.Warn.Printf("Warning: The underlying filesystem " +
					"does not support fallocate(2). gocryptfs will continue working " +
					"but is no longer resistant against out-of-space errors.\n")
			})
			return nil
		}
		return err
	}
}

// Fallocate wraps the Fallocate syscall.
func Fallocate(fd int, mode uint32, off int64, len int64) (err error) {
	return syscall.Fallocate(fd, mode, off, len)
}

// Openat wraps the Openat syscall.
func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	// Why would we ever want to call this without O_NOFOLLOW and O_EXCL?
	if !(flags&syscall.O_CREAT != 0 && flags&syscall.O_EXCL != 0) && flags&syscall.O_NOFOLLOW == 0 {
		tlog.Warn.Printf("Openat: adding missing O_NOFOLLOW flag")
		flags |= syscall.O_NOFOLLOW
	}
	return syscall.Openat(dirfd, path, flags, mode)
}

// Renameat wraps the Renameat syscall.
func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error) {
	return syscall.Renameat(olddirfd, oldpath, newdirfd, newpath)
}

// Unlinkat syscall.
func Unlinkat(dirfd int, path string, flags int) (err error) {
	return unix.Unlinkat(dirfd, path, flags)
}

// Mknodat wraps the Mknodat syscall.
func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	return syscall.Mknodat(dirfd, path, mode, dev)
}

// Dup3 wraps the Dup3 syscall. We want to use Dup3 rather than Dup2 because Dup2
// is not implemented on arm64.
func Dup3(oldfd int, newfd int, flags int) (err error) {
	return syscall.Dup3(oldfd, newfd, flags)
}

// Fchmodat syscall.
func Fchmodat(dirfd int, path string, mode uint32, flags int) (err error) {
	// Linux does not support passing flags to fchmodat! From the man page:
	// AT_SYMLINK_NOFOLLOW ... This flag is not currently implemented.
	// Linux ignores any flags, but Go stdlib rejects them with EOPNOTSUPP starting
	// with Go 1.11. See https://github.com/golang/go/issues/20130 for more info.
	// TODO: Use fchmodat2 once available on Linux.
	return syscall.Fchmodat(dirfd, path, mode, 0)
}

// Fchownat syscall.
func Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error) {
	// Why would we ever want to call this without AT_SYMLINK_NOFOLLOW?
	if flags&unix.AT_SYMLINK_NOFOLLOW == 0 {
		tlog.Warn.Printf("Fchownat: adding missing AT_SYMLINK_NOFOLLOW flag")
		flags |= unix.AT_SYMLINK_NOFOLLOW
	}
	return syscall.Fchownat(dirfd, path, uid, gid, flags)
}

// Symlinkat syscall.
func Symlinkat(oldpath string, newdirfd int, newpath string) (err error) {
	return unix.Symlinkat(oldpath, newdirfd, newpath)
}

// Mkdirat syscall.
func Mkdirat(dirfd int, path string, mode uint32) (err error) {
	return syscall.Mkdirat(dirfd, path, mode)
}

// Fstatat syscall.
func Fstatat(dirfd int, path string, stat *unix.Stat_t, flags int) (err error) {
	// Why would we ever want to call this without AT_SYMLINK_NOFOLLOW?
	if flags&unix.AT_SYMLINK_NOFOLLOW == 0 {
		tlog.Warn.Printf("Fstatat: adding missing AT_SYMLINK_NOFOLLOW flag")
		flags |= unix.AT_SYMLINK_NOFOLLOW
	}
	return unix.Fstatat(dirfd, path, stat, flags)
}

// Getdents syscall.
func Getdents(fd int) ([]fuse.DirEntry, error) {
	return getdents(fd)
}
