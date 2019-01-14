package syscallcompat

import (
	"log"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// O_DIRECT means oncached I/O on Linux. No direct equivalent on MacOS and defined
	// to zero there.
	O_DIRECT = 0

	// O_PATH is only defined on Linux
	O_PATH = 0

	// KAUTH_UID_NONE and KAUTH_GID_NONE are special values to
	// revert permissions to the process credentials.
	KAUTH_UID_NONE = ^uint32(0) - 100
	KAUTH_GID_NONE = ^uint32(0) - 100
)

// Unfortunately pthread_setugid_np does not have a syscall wrapper yet.
func pthread_setugid_np(uid uint32, gid uint32) (err error) {
	_, _, e1 := syscall.RawSyscall(syscall.SYS_SETTID, uintptr(uid), uintptr(gid), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// Sorry, fallocate is not available on OSX at all and
// fcntl F_PREALLOCATE is not accessible from Go.
// See https://github.com/rfjakob/gocryptfs/issues/18 if you want to help.
func EnospcPrealloc(fd int, off int64, len int64) error {
	return nil
}

// See above.
func Fallocate(fd int, mode uint32, off int64, len int64) error {
	return syscall.EOPNOTSUPP
}

// Dup3 is not available on Darwin, so we use Dup2 instead.
func Dup3(oldfd int, newfd int, flags int) (err error) {
	if flags != 0 {
		log.Panic("darwin does not support dup3 flags")
	}
	return syscall.Dup2(oldfd, newfd)
}

////////////////////////////////////////////////////////
//// Emulated Syscalls (see emulate.go) ////////////////
////////////////////////////////////////////////////////

func OpenatUser(dirfd int, path string, flags int, mode uint32, context *fuse.Context) (fd int, err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = pthread_setugid_np(context.Owner.Uid, context.Owner.Gid)
		if err != nil {
			return -1, err
		}
		defer pthread_setugid_np(KAUTH_UID_NONE, KAUTH_GID_NONE)
	}

	return Openat(dirfd, path, flags, mode)
}

func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	return emulateMknodat(dirfd, path, mode, dev)
}

func MknodatUser(dirfd int, path string, mode uint32, dev int, context *fuse.Context) (err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = pthread_setugid_np(context.Owner.Uid, context.Owner.Gid)
		if err != nil {
			return err
		}
		defer pthread_setugid_np(KAUTH_UID_NONE, KAUTH_GID_NONE)
	}

	return Mknodat(dirfd, path, mode, dev)
}

func Fchmodat(dirfd int, path string, mode uint32, flags int) (err error) {
	// Why would we ever want to call this without AT_SYMLINK_NOFOLLOW?
	if flags&unix.AT_SYMLINK_NOFOLLOW == 0 {
		tlog.Warn.Printf("Fchmodat: adding missing AT_SYMLINK_NOFOLLOW flag")
		flags |= unix.AT_SYMLINK_NOFOLLOW
	}
	return unix.Fchmodat(dirfd, path, mode, flags)
}

func SymlinkatUser(oldpath string, newdirfd int, newpath string, context *fuse.Context) (err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = pthread_setugid_np(context.Owner.Uid, context.Owner.Gid)
		if err != nil {
			return err
		}
		defer pthread_setugid_np(KAUTH_UID_NONE, KAUTH_GID_NONE)
	}

	return Symlinkat(oldpath, newdirfd, newpath)
}

func MkdiratUser(dirfd int, path string, mode uint32, context *fuse.Context) (err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = pthread_setugid_np(context.Owner.Uid, context.Owner.Gid)
		if err != nil {
			return err
		}
		defer pthread_setugid_np(KAUTH_UID_NONE, KAUTH_GID_NONE)
	}

	return Mkdirat(dirfd, path, mode)
}

func Getdents(fd int) ([]fuse.DirEntry, error) {
	return emulateGetdents(fd)
}
