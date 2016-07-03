package syscallcompat

import (
	"os"
	"sync"
	"syscall"
)

// prealloc - preallocate space without changing the file size. This prevents
// us from running out of space in the middle of an operation.
func Prealloc(fd int, off int64, len int64) (err error) {
	//
	// Sorry, fallocate is not available on OSX at all and
	// fcntl F_PREALLOCATE is not accessible from Go.
	//
	// See https://github.com/rfjakob/gocryptfs/issues/18 if you want to help.
	return nil
}

var openatLock sync.Mutex

// Poor man's Openat:
// 1) fchdir to the dirfd
// 2) open the file
// 3) chdir back.
func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	openatLock.Lock()
	defer openatLock.Unlock()

	oldWd, err := os.Getwd()
	if err != nil {
		return -1, err
	}
	err = syscall.Fchdir(dirfd)
	if err != nil {
		return -1, err
	}
	defer os.Chdir(oldWd)

	return syscall.Open(path, flags, mode)
}

func Fallocate(fd int, mode uint32, off int64, len int64) (err error) {
	return syscall.EOPNOTSUPP
}
