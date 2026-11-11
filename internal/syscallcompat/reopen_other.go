//go:build !linux

package syscallcompat

import (
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// ReopenFd opens the file referenced by "fd" again, with new "flags".
//
// There is no /proc/self/fd outside Linux, so we reopen "name" relative to
// "dirfd" and verify that we got the same file as "fd". If "name" has been
// replaced by a different file in the meantime, EAGAIN is returned.
// Retries on EINTR.
func ReopenFd(fd int, dirfd int, name string, flags int) (int, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return -1, err
	}
	fd2, err := Openat(dirfd, name, flags, 0)
	if err != nil {
		return -1, err
	}
	var st2 syscall.Stat_t
	if err := syscall.Fstat(fd2, &st2); err != nil {
		syscall.Close(fd2)
		return -1, err
	}
	if st2.Dev != st.Dev || st2.Ino != st.Ino {
		tlog.Warn.Printf("ReopenFd: %q was replaced concurrently, returning EAGAIN", name)
		syscall.Close(fd2)
		return -1, syscall.EAGAIN
	}
	return fd2, nil
}
