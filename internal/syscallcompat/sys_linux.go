// Package syscallcompat wraps Linux-specific syscalls.
package syscallcompat

import (
	"fmt"
	"io/ioutil"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	_FALLOC_FL_KEEP_SIZE = 0x01

	// O_DIRECT means oncached I/O on Linux. No direct equivalent on MacOS and defined
	// to zero there.
	O_DIRECT = syscall.O_DIRECT

	// O_PATH is only defined on Linux
	O_PATH = unix.O_PATH

	// RENAME_NOREPLACE is only defined on Linux
	RENAME_NOREPLACE = unix.RENAME_NOREPLACE
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

func getSupplementaryGroups(pid uint32) (gids []int) {
	procPath := fmt.Sprintf("/proc/%d/task/%d/status", pid, pid)
	blob, err := ioutil.ReadFile(procPath)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(blob), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Groups:") {
			f := strings.Fields(line[7:])
			gids = make([]int, len(f))
			for i := range gids {
				val, err := strconv.ParseInt(f[i], 10, 32)
				if err != nil {
					return nil
				}
				gids[i] = int(val)
			}
			return gids
		}
	}

	return nil
}

// OpenatUser runs the Openat syscall in the context of a different user.
func OpenatUser(dirfd int, path string, flags int, mode uint32, context *fuse.Context) (fd int, err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = syscall.Setgroups(getSupplementaryGroups(context.Pid))
		if err != nil {
			return -1, err
		}
		defer syscall.Setgroups(nil)

		err = syscall.Setregid(-1, int(context.Owner.Gid))
		if err != nil {
			return -1, err
		}
		defer syscall.Setregid(-1, 0)

		err = syscall.Setreuid(-1, int(context.Owner.Uid))
		if err != nil {
			return -1, err
		}
		defer syscall.Setreuid(-1, 0)
	}

	return Openat(dirfd, path, flags, mode)
}

// Mknodat wraps the Mknodat syscall.
func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	return syscall.Mknodat(dirfd, path, mode, dev)
}

// MknodatUser runs the Mknodat syscall in the context of a different user.
func MknodatUser(dirfd int, path string, mode uint32, dev int, context *fuse.Context) (err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = syscall.Setgroups(getSupplementaryGroups(context.Pid))
		if err != nil {
			return err
		}
		defer syscall.Setgroups(nil)

		err = syscall.Setregid(-1, int(context.Owner.Gid))
		if err != nil {
			return err
		}
		defer syscall.Setregid(-1, 0)

		err = syscall.Setreuid(-1, int(context.Owner.Uid))
		if err != nil {
			return err
		}
		defer syscall.Setreuid(-1, 0)
	}

	return Mknodat(dirfd, path, mode, dev)
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

// SymlinkatUser runs the Symlinkat syscall in the context of a different user.
func SymlinkatUser(oldpath string, newdirfd int, newpath string, context *fuse.Context) (err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = syscall.Setgroups(getSupplementaryGroups(context.Pid))
		if err != nil {
			return err
		}
		defer syscall.Setgroups(nil)

		err = syscall.Setregid(-1, int(context.Owner.Gid))
		if err != nil {
			return err
		}
		defer syscall.Setregid(-1, 0)

		err = syscall.Setreuid(-1, int(context.Owner.Uid))
		if err != nil {
			return err
		}
		defer syscall.Setreuid(-1, 0)
	}

	return Symlinkat(oldpath, newdirfd, newpath)
}

// MkdiratUser runs the Mkdirat syscall in the context of a different user.
func MkdiratUser(dirfd int, path string, mode uint32, caller *fuse.Caller) (err error) {
	if caller != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = syscall.Setgroups(getSupplementaryGroups(caller.Pid))
		if err != nil {
			return err
		}
		defer syscall.Setgroups(nil)

		err = syscall.Setregid(-1, int(caller.Gid))
		if err != nil {
			return err
		}
		defer syscall.Setregid(-1, 0)

		err = syscall.Setreuid(-1, int(caller.Uid))
		if err != nil {
			return err
		}
		defer syscall.Setreuid(-1, 0)
	}

	return Mkdirat(dirfd, path, mode)
}

func timesToTimespec(a *time.Time, m *time.Time) []unix.Timespec {
	ts := make([]unix.Timespec, 2)
	ts[0] = unix.Timespec(fuse.UtimeToTimespec(a))
	ts[1] = unix.Timespec(fuse.UtimeToTimespec(m))
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

// Getdents syscall.
func Getdents(fd int) ([]fuse.DirEntry, error) {
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
