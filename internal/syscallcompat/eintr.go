package syscallcompat

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// retryEINTR executes operation `op` and retries if it gets EINTR.
//
// Like ignoringEINTR() in the Go stdlib:
// https://github.com/golang/go/blob/d2a80f3fb5b44450e0b304ac5a718f99c053d82a/src/os/file_posix.go#L243
//
// This is needed because CIFS throws lots of EINTR errors:
// https://github.com/rfjakob/gocryptfs/issues/483
//
// Don't use retryEINTR() with syscall.Close()!
// See https://code.google.com/p/chromium/issues/detail?id=269623 .
func retryEINTR(op func() error) error {
	for {
		err := op()
		if err != syscall.EINTR {
			return err
		}
	}
}

// retryEINTR2 is like retryEINTR but for functions that return an (int, error)
// pair like syscall.Create().
func retryEINTR2(op func() (int, error)) (int, error) {
	for {
		ret, err := op()
		if err != syscall.EINTR {
			return ret, err
		}
	}
}

// Open wraps syscall.Open.
// Retries on EINTR.
func Open(path string, mode int, perm uint32) (fd int, err error) {
	fd, err = retryEINTR2(func() (int, error) {
		return syscall.Open(path, mode, perm)
	})
	return fd, err
}

// Renameat wraps the Renameat syscall.
// Retries on EINTR.
func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error) {
	err = retryEINTR(func() error {
		return unix.Renameat(olddirfd, oldpath, newdirfd, newpath)
	})
	return err
}

// Unlinkat syscall.
// Retries on EINTR.
func Unlinkat(dirfd int, path string, flags int) (err error) {
	err = retryEINTR(func() error {
		return unix.Unlinkat(dirfd, path, flags)
	})
	return err
}

// Flush is a helper for the FUSE command FLUSH.
// Retries on EINTR.
func Flush(fd int) error {
	for {
		// Flushing is achieved by closing a dup'd fd.
		newFd, err := syscall.Dup(fd)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		err = syscall.Close(newFd)
		// Even if we get EINTR here, newFd is dead - see
		// https://code.google.com/p/chromium/issues/detail?id=269623 .
		// We have to make a new one with Dup(), so continue at the top.
		if err == syscall.EINTR {
			continue
		}
		return err
	}
}
