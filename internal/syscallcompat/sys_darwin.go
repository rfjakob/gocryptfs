package syscallcompat

import (
	"log"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	// O_DIRECT means uncached I/O on Linux. No direct equivalent on MacOS and defined
	// to zero there.
	O_DIRECT = 0

	// O_PATH is only defined on Linux
	O_PATH = 0

	// Only exists on Linux. Define here to fix build failure, even though
	// we will never see the flags.
	RENAME_NOREPLACE = 1
	RENAME_EXCHANGE  = 2
	RENAME_WHITEOUT  = 4

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

// Unfortunately fsetattrlist does not have a syscall wrapper yet.
func fsetattrlist(fd int, list unsafe.Pointer, buf unsafe.Pointer, size uintptr, options int) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_FSETATTRLIST, uintptr(fd), uintptr(list), uintptr(buf), uintptr(size), uintptr(options), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// Setattrlist already has a syscall wrapper, but it is not exported.
func setattrlist(path *byte, list unsafe.Pointer, buf unsafe.Pointer, size uintptr, options int) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_SETATTRLIST, uintptr(unsafe.Pointer(path)), uintptr(list), uintptr(buf), uintptr(size), uintptr(options), 0)
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

func FchmodatNofollow(dirfd int, path string, mode uint32) (err error) {
	return unix.Fchmodat(dirfd, path, mode, unix.AT_SYMLINK_NOFOLLOW)
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

	return unix.Symlinkat(oldpath, newdirfd, newpath)
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

	return unix.Mkdirat(dirfd, path, mode)
}

type attrList struct {
	bitmapCount uint16
	_           uint16
	CommonAttr  uint32
	VolAttr     uint32
	DirAttr     uint32
	FileAttr    uint32
	Forkattr    uint32
}

func timesToAttrList(a *time.Time, m *time.Time) (attrList attrList, attributes [2]unix.Timespec) {
	attrList.bitmapCount = unix.ATTR_BIT_MAP_COUNT
	attrList.CommonAttr = 0
	i := 0
	if m != nil {
		attributes[i] = unix.Timespec(fuse.UtimeToTimespec(m))
		attrList.CommonAttr |= unix.ATTR_CMN_MODTIME
		i += 1
	}
	if a != nil {
		attributes[i] = unix.Timespec(fuse.UtimeToTimespec(a))
		attrList.CommonAttr |= unix.ATTR_CMN_ACCTIME
		i += 1
	}
	return attrList, attributes
}

// FutimesNano syscall.
func FutimesNano(fd int, a *time.Time, m *time.Time) (err error) {
	attrList, attributes := timesToAttrList(a, m)
	return fsetattrlist(fd, unsafe.Pointer(&attrList), unsafe.Pointer(&attributes),
		unsafe.Sizeof(attributes), 0)
}

// UtimesNanoAtNofollow is like UtimesNanoAt but never follows symlinks.
//
// Unfortunately we cannot use unix.UtimesNanoAt since it is broken and just
// ignores the provided 'dirfd'. In addition, it also lacks handling of 'nil'
// pointers (used to preserve one of both timestamps).
func UtimesNanoAtNofollow(dirfd int, path string, a *time.Time, m *time.Time) (err error) {
	if !filepath.IsAbs(path) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		var cwd int
		cwd, err = syscall.Open(".", syscall.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer syscall.Close(cwd)
		err = syscall.Fchdir(dirfd)
		if err != nil {
			return err
		}
		defer syscall.Fchdir(cwd)
	}

	_p0, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}

	attrList, attributes := timesToAttrList(a, m)
	return setattrlist(_p0, unsafe.Pointer(&attrList), unsafe.Pointer(&attributes),
		unsafe.Sizeof(attributes), unix.FSOPT_NOFOLLOW)
}

func Getdents(fd int) ([]fuse.DirEntry, error) {
	entries, _, err := emulateGetdents(fd)
	return entries, err
}

func GetdentsSpecial(fd int) (entries []fuse.DirEntry, entriesSpecial []fuse.DirEntry, err error) {
	return emulateGetdents(fd)
}

// Renameat2 does not exist on Darwin, so we call Renameat and ignore the flags.
func Renameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) (err error) {
	return unix.Renameat(olddirfd, oldpath, newdirfd, newpath)
}
