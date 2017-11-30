package syscallcompat

import (
	"log"
	"syscall"
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

func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error) {
	return emulateRenameat(olddirfd, oldpath, newdirfd, newpath)
}

func Unlinkat(dirfd int, path string, flags int) (err error) {
	return emulateUnlinkat(dirfd, path, flags)
}

func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	return emulateMknodat(dirfd, path, mode, dev)
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

func Mkdirat(dirfd int, path string, mode uint32) (err error) {
	return emulateMkdirat(dirfd, path, mode)
}
