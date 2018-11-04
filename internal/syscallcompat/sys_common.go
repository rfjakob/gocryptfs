package syscallcompat

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// PATH_MAX is the maximum allowed path length on Linux.
// It is not defined on Darwin, so we use the Linux value.
const PATH_MAX = 4096

// Readlinkat is a convenience wrapper around unix.Readlinkat() that takes
// care of buffer sizing. Implemented like os.Readlink().
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

// Faccessat exists both in Linux and in MacOS 10.10+, but the Linux version
// DOES NOT support any flags. Emulate AT_SYMLINK_NOFOLLOW like glibc does.
func Faccessat(dirfd int, path string, mode uint32) error {
	var st unix.Stat_t
	err := Fstatat(dirfd, path, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		// Pretend that a symlink is always accessible
		return nil
	}
	return unix.Faccessat(dirfd, path, mode, 0)
}

// Linkat exists both in Linux and in MacOS 10.10+.
func Linkat(olddirfd int, oldpath string, newdirfd int, newpath string, flags int) (err error) {
	return unix.Linkat(olddirfd, oldpath, newdirfd, newpath, flags)
}
