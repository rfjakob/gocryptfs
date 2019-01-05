package ensurestdfds

import (
	"os"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
)

// init() ensures that file descriptors 0,1,2 are open. The Go stdlib,
// as well as the gocryptfs code, relies on the fact that fds 0,1,2 are always
// open.
// See https://github.com/rfjakob/gocryptfs/issues/320 for details.
func init() {
	fd, err := syscall.Open("/dev/null", syscall.O_RDWR, 0)
	if err != nil {
		os.Exit(exitcodes.DevNull)
	}
	for fd <= 2 {
		fd, err = syscall.Dup(fd)
		if err != nil {
			os.Exit(exitcodes.DevNull)
		}
	}
	// Close excess fd (usually fd 3)
	syscall.Close(fd)
}
