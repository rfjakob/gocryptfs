package syscallcompat

import (
	"syscall"
)

// retryEINTR executes operation `op` and retries if it gets EINTR.
//
// Like ignoringEINTR() in the Go stdlib:
// https://github.com/golang/go/blob/d2a80f3fb5b44450e0b304ac5a718f99c053d82a/src/os/file_posix.go#L243
//
// This is needed because CIFS throws lots of EINTR errors:
// https://github.com/rfjakob/gocryptfs/issues/483
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

// Close wraps syscall.Close.
// Retries on EINTR.
func Close(fd int) (err error) {
	err = retryEINTR(func() error { return syscall.Close(fd) })
	return err
}
