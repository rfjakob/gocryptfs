package syscallcompat

import (
	"path/filepath"
	"sync"
	"syscall"
)

var chdirMutex sync.Mutex

// emulateMknodat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateMknodat(dirfd int, path string, mode uint32, dev int) error {
	if !filepath.IsAbs(path) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		cwd, err := syscall.Open(".", syscall.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer syscall.Close(cwd)
		err = syscall.Fchdir(dirfd)
		if err != nil {
			return err
		}
		defer syscall.Fchdir(cwd)
	}
	return syscall.Mknod(path, mode, dev)
}
