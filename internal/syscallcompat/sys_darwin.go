package syscallcompat

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
