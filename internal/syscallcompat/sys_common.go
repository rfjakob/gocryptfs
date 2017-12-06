package syscallcompat

import (
	"golang.org/x/sys/unix"
)

// Readlinkat exists both in Linux and in MacOS 10.10+. We may add an
// emulated version for users on older MacOS versions if there is
// demand.
// Buffer allocation is handled internally, unlike the bare unix.Readlinkat.
func Readlinkat(dirfd int, path string) (string, error) {
	// Allocate the buffer exponentially like os.Readlink does.
	for bufsz := 128; ; bufsz *= 2 {
		buf := make([]byte, bufsz)
		n, err := unix.Readlinkat(dirfd, path, buf)
		if err != nil {
			return "", err
		}
		if n < bufsz {
			return string(buf[0:n]), nil
		}
	}
}
