package fusefrontend

import "syscall"

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
		return err
	}
}
