// Package syscallcompat wraps Linux-specific syscalls.
package syscallcompat

import (
	"fmt"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	_FALLOC_FL_KEEP_SIZE = 0x01

	// O_DIRECT means oncached I/O on Linux. No direct equivalent on MacOS and defined
	// to zero there.
	O_DIRECT = syscall.O_DIRECT

	// O_PATH is only defined on Linux
	O_PATH = unix.O_PATH

	// Only defined on Linux
	RENAME_NOREPLACE = unix.RENAME_NOREPLACE
	RENAME_WHITEOUT  = unix.RENAME_WHITEOUT
	RENAME_EXCHANGE  = unix.RENAME_EXCHANGE

	// Only defined on Linux
	ENODATA = unix.ENODATA

	// On Darwin we use O_SYMLINK which allows opening a symlink itself.
	// On Linux, we only have O_NOFOLLOW.
	OpenatFlagNofollowSymlink = unix.O_NOFOLLOW
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

// Mknodat wraps the Mknodat syscall.
func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	return syscall.Mknodat(dirfd, path, mode, dev)
}

// Dup3 wraps the Dup3 syscall. We want to use Dup3 rather than Dup2 because Dup2
// is not implemented on arm64.
func Dup3(oldfd int, newfd int, flags int) (err error) {
	return syscall.Dup3(oldfd, newfd, flags)
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
	fd, err := syscall.Openat(dirfd, path, syscall.O_NOFOLLOW|O_PATH, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// Now we can check the type without the risk of race-conditions.
	// Return syscall.ELOOP if it is a symlink.
	var st syscall.Stat_t
	err = syscall.Fstat(fd, &st)
	if err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		return syscall.ELOOP
	}

	// Change mode of the actual file. Fchmod does not work with O_PATH,
	// but Chmod via /proc/self/fd works.
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	return syscall.Chmod(procPath, mode)
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
	entries, _, err := getdents(fd)
	return entries, err
}

// GetdentsSpecial calls the Getdents syscall,
// with normal entries and "." / ".." split into two slices.
func GetdentsSpecial(fd int) (entries []fuse.DirEntry, entriesSpecial []fuse.DirEntry, err error) {
	return getdents(fd)
}

// Renameat2 does not exist on Darwin, so we have to wrap it here.
// Retries on EINTR.
func Renameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) (err error) {
	err = retryEINTR(func() error {
		return unix.Renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
	})
	return err
}
