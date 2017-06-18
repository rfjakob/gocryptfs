// Package syscallcompat wraps Linux-specific syscalls.
package syscallcompat

import (
	"sync"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const _FALLOC_FL_KEEP_SIZE = 0x01

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
	return syscall.Openat(dirfd, path, flags, mode)
}

// Renameat wraps the Renameat syscall.
func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error) {
	return syscall.Renameat(olddirfd, oldpath, newdirfd, newpath)
}

// Unlinkat wraps the Unlinkat syscall.
func Unlinkat(dirfd int, path string) error {
	return syscall.Unlinkat(dirfd, path)
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
