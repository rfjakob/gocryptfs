package syscallcompat

import (
	"log"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"
)

const (
	// O_DIRECT means oncached I/O on Linux. No direct equivalent on MacOS and defined
	// to zero there.
	O_DIRECT = 0

	// O_PATH is only defined on Linux
	O_PATH = 0
)

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

func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	return emulateOpenat(dirfd, path, flags, mode)
}

func OpenatUser(dirfd int, path string, flags int, mode uint32, context *fuse.Context) (fd int, err error) {
	// FIXME: take into account context.Owner
	return Openat(dirfd, path, flags, mode)
}

func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error) {
	return emulateRenameat(olddirfd, oldpath, newdirfd, newpath)
}

func Unlinkat(dirfd int, path string, flags int) (err error) {
	return emulateUnlinkat(dirfd, path, flags)
}

func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	return emulateMknodat(dirfd, path, mode, dev)
}

func MknodatUser(dirfd int, path string, mode uint32, dev int, context *fuse.Context) (err error) {
	// FIXME: take into account context.Owner
	return Mknodat(dirfd, path, mode, dev)
}

func Fchmodat(dirfd int, path string, mode uint32, flags int) (err error) {
	return emulateFchmodat(dirfd, path, mode, flags)
}

func Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error) {
	return emulateFchownat(dirfd, path, uid, gid, flags)
}

func Symlinkat(oldpath string, newdirfd int, newpath string) (err error) {
	return emulateSymlinkat(oldpath, newdirfd, newpath)
}

func SymlinkatUser(oldpath string, newdirfd int, newpath string, context *fuse.Context) (err error) {
	// FIXME: take into account context.Owner
	return Symlinkat(oldpath, newdirfd, newpath)
}

func Mkdirat(dirfd int, path string, mode uint32) (err error) {
	return emulateMkdirat(dirfd, path, mode)
}

func MkdiratUser(dirfd int, path string, mode uint32, context *fuse.Context) (err error) {
	// FIXME: take into account context.Owner
	return Mkdirat(dirfd, path, mode)
}

func Fstatat(dirfd int, path string, stat *unix.Stat_t, flags int) (err error) {
	return emulateFstatat(dirfd, path, stat, flags)
}

func Getdents(fd int) ([]fuse.DirEntry, error) {
	return emulateGetdents(fd)
}
