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

// asUser runs `f()` under the effective uid, gid, groups specified
// in `context`.
//
// If `context` is nil, `f()` is executed directly without switching user id.
func asUser(f func() (int, error), context *fuse.Context) (int, error) {
	if context == nil {
		return f()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Since go1.16beta1 (commit d1b1145cace8b968307f9311ff611e4bb810710c ,
	// https://go-review.googlesource.com/c/go/+/210639 )
	// syscall.{Setgroups,Setregid,Setreuid} affects all threads, which
	// is exactly what we not want.
	//
	// We now use unix.{Setgroups,Setregid,Setreuid} instead.

	err := unix.Setgroups(getSupplementaryGroups(context.Pid))
	if err != nil {
		return -1, err
	}
	defer unix.Setgroups(nil)

	err = unix.Setregid(-1, int(context.Owner.Gid))
	if err != nil {
		return -1, err
	}
	defer unix.Setregid(-1, 0)

	err = unix.Setreuid(-1, int(context.Owner.Uid))
	if err != nil {
		return -1, err
	}
	defer unix.Setreuid(-1, 0)

	return f()
}

// OpenatUser runs the Openat syscall in the context of a different user.
//
// It switches the current thread to the new user, performs the syscall,
// and switches back.
//
// If `context` is nil, this function behaves like ordinary Openat (no
// user switching).
func OpenatUser(dirfd int, path string, flags int, mode uint32, context *fuse.Context) (fd int, err error) {
	f := func() (int, error) {
		return Openat(dirfd, path, flags, mode)
	}
	return asUser(f, context)
}

// Mknodat wraps the Mknodat syscall.
func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	return syscall.Mknodat(dirfd, path, mode, dev)
}

// MknodatUser runs the Mknodat syscall in the context of a different user.
// If `context` is nil, this function behaves like ordinary Mknodat.
//
// See OpenatUser() for how this works.
func MknodatUser(dirfd int, path string, mode uint32, dev int, context *fuse.Context) (err error) {
	f := func() (int, error) {
		err := Mknodat(dirfd, path, mode, dev)
		return -1, err
	}
	_, err = asUser(f, context)
	return err
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
// If `context` is nil, this function behaves like ordinary Symlinkat.
//
// See OpenatUser() for how this works.
func SymlinkatUser(oldpath string, newdirfd int, newpath string, context *fuse.Context) (err error) {
	f := func() (int, error) {
		err := unix.Symlinkat(oldpath, newdirfd, newpath)
		return -1, err
	}
	_, err = asUser(f, context)
	return err
}

// MkdiratUser runs the Mkdirat syscall in the context of a different user.
// If `context` is nil, this function behaves like ordinary Mkdirat.
//
// See OpenatUser() for how this works.
func MkdiratUser(dirfd int, path string, mode uint32, context *fuse.Context) (err error) {
	f := func() (int, error) {
		err := unix.Mkdirat(dirfd, path, mode)
		return -1, err
	}
	_, err = asUser(f, context)
	return err
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
