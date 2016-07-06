// Package syscallcompat wraps Linux-specific syscalls.
package syscallcompat

import (
	"sync"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const FALLOC_FL_KEEP_SIZE = 0x01

var preallocWarn sync.Once

// EnospcPrealloc preallocates ciphertext space without changing the file
// size. This guarantees that we don't run out of space while writing a
// ciphertext block (that would corrupt the block).
func EnospcPrealloc(fd int, off int64, len int64) (err error) {
	for {
		err = syscall.Fallocate(fd, FALLOC_FL_KEEP_SIZE, off, len)
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

func Fallocate(fd int, mode uint32, off int64, len int64) (err error) {
	return syscall.Fallocate(fd, mode, off, len)
}

func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	return syscall.Openat(dirfd, path, flags, mode)
}

func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error) {
	return syscall.Renameat(olddirfd, oldpath, newdirfd, newpath)
}

func Unlinkat(dirfd int, path string) error {
	return syscall.Unlinkat(dirfd, path)
}

func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	return syscall.Mknodat(dirfd, path, mode, dev)
}
