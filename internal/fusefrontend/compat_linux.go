package fusefrontend

import (
	"sync"
	"syscall"
)

import "github.com/rfjakob/gocryptfs/internal/tlog"

var preallocWarn sync.Once

// prealloc - preallocate space without changing the file size. This prevents
// us from running out of space in the middle of an operation.
func prealloc(fd int, off int64, len int64) (err error) {
	for {
		err = syscall.Fallocate(fd, FALLOC_FL_KEEP_SIZE, off, len)
		if err == syscall.EINTR {
			// fallocate, like many syscalls, can return EINTR. This is not an
			// error and just signifies that the operation was interrupted by a
			// signal and we should try again.
			continue
		}
		if err == syscall.EOPNOTSUPP {
			// ZFS does not support fallocate which caused gocryptfs to abort
			// every write operation: https://github.com/rfjakob/gocryptfs/issues/22
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
