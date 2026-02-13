// Package syscallcompat wraps FreeBSD-specific syscalls
package syscallcompat

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	O_DIRECT = unix.O_DIRECT

	// O_PATH is supported on FreeBSD, but is missing from the sys/unix package
	// FreeBSD-15.0 /usr/src/sys/sys/fcntl.h:135
	O_PATH = 0x00400000

	// Only defined on Linux, but we can emulate the functionality on FreeBSD
	// in Renameat2() below
	RENAME_NOREPLACE = 0x1
	RENAME_EXCHANGE  = 0x2
	RENAME_WHITEOUT  = 0x4

	// ENODATA is only defined on Linux, but FreeBSD provides ENOATTR
	ENODATA = unix.ENOATTR

	// On FreeBSD, we only have O_NOFOLLOW.
	OpenatFlagNofollowSymlink = unix.O_NOFOLLOW
)

// EnospcPrealloc is supposed to preallocate ciphertext space without
// changing the file size. This guarantees that we don't run out of
// space while writing a ciphertext block (that would corrupt the block).
//
// The fallocate syscall isn't supported on FreeBSD with the same semantics
// as Linux, in particular the _FALLOC_FL_KEEP_SIZE mode isn't supported.
func EnospcPrealloc(fd int, off int64, len int64) (err error) {
	return nil
}

// Fallocate wraps the posix_fallocate() syscall.
// Fallocate returns an error if mode is not 0
func Fallocate(fd int, mode uint32, off int64, len int64) (err error) {
	if mode != 0 {
		return errors.New("fallocate unsupported mode")
	}
	_, _, err = unix.Syscall(unix.SYS_POSIX_FALLOCATE, uintptr(fd), uintptr(off), uintptr(len))
	return err
}

// Mknodat wraps the Mknodat syscall.
func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	return unix.Mknodat(dirfd, path, mode, uint64(dev))
}

// Dup3 wraps the Dup3 syscall. We want to use Dup3 rather than Dup2 because Dup2
// is not implemented on arm64.
func Dup3(oldfd int, newfd int, flags int) (err error) {
	return unix.Dup3(oldfd, newfd, flags)
}

// FchmodatNofollow is like Fchmodat but never follows symlinks.
//
// This should be handled by the AT_SYMLINK_NOFOLLOW flag, but Linux
// does not implement it, so we have to perform an elaborate dance
// with O_PATH and /proc/self/fd.
//
// See also: Qemu implemented the same logic as fchmodat_nofollow():
// https://git.qemu.org/?p=qemu.git;a=blob;f=hw/9pfs/9p-local.c#l335
func FchmodatNofollow(dirfd int, path string, mode uint32) (err error) {
	// Open handle to the filename (but without opening the actual file).
	// This succeeds even when we don't have read permissions to the file.
	fd, err := unix.Openat(dirfd, path, unix.O_NOFOLLOW|O_PATH, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// Now we can check the type without the risk of race-conditions.
	// Return syscall.ELOOP if it is a symlink.
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return unix.ELOOP
	}

	// Change mode of the actual file. Fchmod does not work with O_PATH,
	// but Chmod via /proc/self/fd works.
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	return unix.Chmod(procPath, mode)
}

// LsetxattrUser runs the Lsetxattr syscall in the context of a different user.
// This is useful when setting ACLs, as the result depends on the user running
// the operation (see fuse-xfstests generic/375).
//
// If `context` is nil, this function behaves like ordinary Lsetxattr.
func LsetxattrUser(path string, attr string, data []byte, flags int, context *fuse.Context) (err error) {
	f := func() (int, error) {
		err := unix.Lsetxattr(path, attr, data, flags)
		return -1, err
	}
	_, err = asUser(f, context)
	return err
}

func timesToTimespec(a *time.Time, m *time.Time) []unix.Timespec {
	ts := make([]unix.Timespec, 2)
	if a == nil {
		ts[0] = unix.Timespec{Nsec: unix.UTIME_OMIT}
	} else {
		ts[0], _ = unix.TimeToTimespec(*a)
	}
	if m == nil {
		ts[1] = unix.Timespec{Nsec: unix.UTIME_OMIT}
	} else {
		ts[1], _ = unix.TimeToTimespec(*m)
	}
	return ts
}

// FutimesNano syscall.
func FutimesNano(fd int, a *time.Time, m *time.Time) (err error) {
	ts := timesToTimespec(a, m)
	// To avoid introducing a separate syscall wrapper for futimens()
	// (as done in go-fuse, for example), we instead use the /proc/self/fd trick.
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	return unix.UtimesNanoAt(unix.AT_FDCWD, procPath, ts, 0)
}

// UtimesNanoAtNofollow is like UtimesNanoAt but never follows symlinks.
// Retries on EINTR.
func UtimesNanoAtNofollow(dirfd int, path string, a *time.Time, m *time.Time) (err error) {
	ts := timesToTimespec(a, m)
	err = retryEINTR(func() error {
		return unix.UtimesNanoAt(dirfd, path, ts, unix.AT_SYMLINK_NOFOLLOW)
	})
	return err
}

// Getdents syscall with "." and ".." filtered out.
func Getdents(fd int) ([]fuse.DirEntry, error) {
	entries, _, err := emulateGetdents(fd)
	return entries, err
}

// GetdentsSpecial calls the Getdents syscall,
// with normal entries and "." / ".." split into two slices.
func GetdentsSpecial(fd int) (entries []fuse.DirEntry, entriesSpecial []fuse.DirEntry, err error) {
	return emulateGetdents(fd)
}

// Renameat2 does not exist on Darwin, so we have to wrap it here.
// Retries on EINTR.
func Renameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) (err error) {
	if flags&(RENAME_NOREPLACE|RENAME_EXCHANGE) == RENAME_NOREPLACE|RENAME_EXCHANGE {
		return unix.EINVAL
	}
	if flags&(RENAME_NOREPLACE|RENAME_EXCHANGE) == RENAME_NOREPLACE|RENAME_EXCHANGE {
		return unix.EINVAL
	}

	if flags&RENAME_NOREPLACE != 0 {
		var st unix.Stat_t
		err = unix.Fstatat(newdirfd, newpath, &st, 0)
		if err == nil {
			// Assume newpath is an existing file if we can stat() it.
			// On Linux, RENAME_NOREPLACE fails with EEXIST if newpath
			// already exists.
			return unix.EEXIST
		}
	}
	if flags&RENAME_EXCHANGE != 0 {
		// Note that on Linux, RENAME_EXCHANGE can handle oldpath and
		// newpath of different file types (e.g. directory and
		// symbolic link). On FreeBSD the file types must be the same.
		var stold, stnew unix.Stat_t
		err = unix.Fstatat(olddirfd, oldpath, &stold, 0)
		if err != nil {
			// Assume file does not exist if we can't stat() it.
			// On Linux, RENAME_EXCHANGE requires both oldpath
			// and newpath exist.
			return unix.ENOENT
		}
		err = unix.Fstatat(newdirfd, newpath, &stnew, 0)
		if err != nil {
			// Assume file does not exist if we can't stat() it.
			// On Linux, RENAME_EXCHANGE requires both oldpath
			// and newpath exist.
			return unix.ENOENT
		}
	}
	if flags&RENAME_WHITEOUT != 0 {
		return unix.EINVAL
	}

	return unix.Renameat(olddirfd, oldpath, newdirfd, newpath)
}
