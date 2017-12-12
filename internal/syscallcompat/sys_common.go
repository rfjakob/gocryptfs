package syscallcompat

import (
	"syscall"

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
