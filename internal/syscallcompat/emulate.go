package syscallcompat

import (
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
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

// emulateFchownat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateFchownat(dirfd int, path string, uid int, gid int, flags int) (err error) {
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
	return syscall.Lchown(path, uid, gid)
}

// emulateSymlinkat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateSymlinkat(oldpath string, newdirfd int, newpath string) (err error) {
	if !filepath.IsAbs(newpath) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		cwd, err := syscall.Open(".", syscall.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer syscall.Close(cwd)
		err = syscall.Fchdir(newdirfd)
		if err != nil {
			return err
		}
		defer syscall.Fchdir(cwd)
	}
	return syscall.Symlink(oldpath, newpath)
}

// emulateMkdirat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateMkdirat(dirfd int, path string, mode uint32) (err error) {
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
	return syscall.Mkdir(path, mode)
}

// emulateFstatat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateFstatat(dirfd int, path string, stat *unix.Stat_t, flags int) (err error) {
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
	return unix.Lstat(path, stat)
}
