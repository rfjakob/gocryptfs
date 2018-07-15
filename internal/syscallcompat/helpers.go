package syscallcompat

import (
	"os"
	"syscall"
)

// IsENOSPC tries to find out if "err" is a (potentially wrapped) ENOSPC error.
func IsENOSPC(err error) bool {
	// syscallcompat.EnospcPrealloc returns the naked syscall error
	if err == syscall.ENOSPC {
		return true
	}
	// os.File.WriteAt returns &PathError
	if err2, ok := err.(*os.PathError); ok {
		if err2.Err == syscall.ENOSPC {
			return true
		}
	}
	return false
}
