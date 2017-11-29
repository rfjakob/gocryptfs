// Package syscallcompat wraps Linux-specific syscalls.
package syscallcompat

import (
	"sync"
	"syscall"
	"unsafe"

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

// Unlinkat syscall. In old versions the 'flags' argument was missing, so
// manually call it by using the corresponding syscall number.
func Unlinkat(dirfd int, path string, flags int) (err error) {
	var _p0 *byte
	_p0, err = syscall.BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(flags))
	if e1 != 0 {
		err = e1
	}
	return
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
	return syscall.Fchmodat(dirfd, path, mode, flags)
}

// Fchownat syscall.
func Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error) {
	return syscall.Fchownat(dirfd, path, uid, gid, flags)
}

// Symlinkat syscall. Unfortunately this function is not exported directly, so
// manually call it by using the corresponding syscall number.
func Symlinkat(oldpath string, newdirfd int, newpath string) (err error) {
	var _p0 *byte
	_p0, err = syscall.BytePtrFromString(oldpath)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = syscall.BytePtrFromString(newpath)
	if err != nil {
		return
	}
	_, _, e1 := syscall.Syscall(syscall.SYS_SYMLINKAT, uintptr(unsafe.Pointer(_p0)), uintptr(newdirfd), uintptr(unsafe.Pointer(_p1)))
	if e1 != 0 {
		err = e1
	}
	return
}

// Mkdirat syscall.
func Mkdirat(dirfd int, path string, mode uint32) (err error) {
	return syscall.Mkdirat(dirfd, path, mode)
}
