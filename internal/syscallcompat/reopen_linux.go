package syscallcompat

import (
	"fmt"
	"syscall"
)

// ReopenFd opens the file referenced by "fd" again, with new "flags".
//
// On Linux, this goes through /proc/self/fd, which always resolves to
// exactly the file "fd" refers to, even if it has been renamed or replaced.
// "dirfd" and "name" are not used. They are needed for the fallback
// implementation on other platforms.
// Retries on EINTR.
func ReopenFd(fd int, dirfd int, name string, flags int) (int, error) {
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	// /proc/self/fd/N is a symlink, so O_NOFOLLOW would make the open fail
	// with ELOOP. Following it is safe because it is a "magic link" that
	// points to the open file description, not to a path.
	flags = flags&^syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	return retryEINTR2(func() (int, error) {
		return syscall.Open(procPath, flags, 0)
	})
}
