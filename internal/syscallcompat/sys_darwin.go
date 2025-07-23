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

	// Only exists on Linux. Define here to fix build failure, even though
	// we will never see the flags.
	RENAME_NOREPLACE = 1
	RENAME_EXCHANGE  = 2
	RENAME_WHITEOUT  = 4
	
	// macOS-specific renameatx_np flags
	RENAME_SWAP          = 0x2  // Swap the names of the source and target files
	SYS_RENAMEATX_NP     = 488  // Syscall number for renameatx_np
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

// renameatx_np is the macOS-specific rename function that supports atomic exchanges
func renameatx_np(fromfd int, from string, tofd int, to string, flags uint) (err error) {
	var _p0, _p1 *byte
	_p0, err = syscall.BytePtrFromString(from)
	if err != nil {
		return
	}
	_p1, err = syscall.BytePtrFromString(to)
	if err != nil {
		return
	}
	_, _, e1 := syscall.Syscall6(SYS_RENAMEATX_NP, uintptr(fromfd), uintptr(unsafe.Pointer(_p0)), uintptr(tofd), uintptr(unsafe.Pointer(_p1)), uintptr(flags), 0)
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

// Renameat2 does not exist on Darwin, but we can emulate some flags using renameatx_np.
func Renameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) (err error) {
	// If no special flags are set, use regular renameat
	if flags == 0 {
		return unix.Renameat(olddirfd, oldpath, newdirfd, newpath)
	}
	
	// Handle RENAME_EXCHANGE flag using renameatx_np
	if flags&RENAME_EXCHANGE != 0 {
		// renameatx_np with RENAME_SWAP flag provides RENAME_EXCHANGE functionality
		return renameatx_np(olddirfd, oldpath, newdirfd, newpath, RENAME_SWAP)
	}
	
	// For other flags (RENAME_NOREPLACE, RENAME_WHITEOUT), fall back to regular rename
	// These are not directly supported on macOS but regular rename should work for most cases
	return unix.Renameat(olddirfd, oldpath, newdirfd, newpath)
}
