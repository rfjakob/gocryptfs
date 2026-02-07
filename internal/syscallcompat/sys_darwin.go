package syscallcompat

import (
	"log"
	"path/filepath"
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

	// Same meaning, different name
	RENAME_NOREPLACE = unix.RENAME_EXCL
	RENAME_EXCHANGE  = unix.RENAME_SWAP

	// Only exists on Linux. Define here to fix build failure, even though
	// we will never see this flag.
	RENAME_WHITEOUT = 1 << 30

	// On Darwin we use O_SYMLINK which allows opening a symlink itself.
	// On Linux, we only have O_NOFOLLOW.
	OpenatFlagNofollowSymlink = unix.O_SYMLINK
)

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

func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	return emulateMknodat(dirfd, path, mode, dev)
}

func FchmodatNofollow(dirfd int, path string, mode uint32) (err error) {
	return unix.Fchmodat(dirfd, path, mode, unix.AT_SYMLINK_NOFOLLOW)
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

// Renameat2 does not exist on Darwin, but RenameatxNp does.
func Renameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) (err error) {
	// If no flags are set, use tried and true renameat
	if flags == 0 {
		return unix.Renameat(olddirfd, oldpath, newdirfd, newpath)
	}
	// Let RenameatxNp handle everything else
	return unix.RenameatxNp(olddirfd, oldpath, newdirfd, newpath, uint32(flags))
}
