package syscallcompat

import (
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

var chdirMutex sync.Mutex

// emulateOpenat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateOpenat(dirfd int, path string, flags int, mode uint32) (int, error) {
	if !filepath.IsAbs(path) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		cwd, err := unix.Open(".", unix.O_RDONLY, 0)
		if err != nil {
			return -1, err
		}
		defer unix.Close(cwd)
		err = unix.Fchdir(dirfd)
		if err != nil {
			return -1, err
		}
		defer unix.Fchdir(cwd)
	}
	return unix.Open(path, flags, mode)
}

// emulateRenameat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateRenameat(olddirfd int, oldpath string, newdirfd int, newpath string) error {
	chdirMutex.Lock()
	defer chdirMutex.Unlock()
	// Unless both paths are absolute we have to save the old working dir and
	// Chdir(oldWd) back to it in the end. If we error out before the first
	// chdir, Chdir(oldWd) is unneccassary but does no harm.
	if !filepath.IsAbs(oldpath) || !filepath.IsAbs(newpath) {
		oldWd, err := os.Getwd()
		if err != nil {
			return err
		}
		defer os.Chdir(oldWd)
	}
	// Make oldpath absolute
	oldpath, err := dirfdAbs(olddirfd, oldpath)
	if err != nil {
		return err
	}
	// Make newpath absolute
	newpath, err = dirfdAbs(newdirfd, newpath)
	if err != nil {
		return err
	}
	return unix.Rename(oldpath, newpath)
}

// emulateUnlinkat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateUnlinkat(dirfd int, path string, flags int) (err error) {
	if !filepath.IsAbs(path) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		cwd, err := unix.Open(".", unix.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer unix.Close(cwd)
		err = unix.Fchdir(dirfd)
		if err != nil {
			return err
		}
		defer unix.Fchdir(cwd)
	}
	if (flags & unix.AT_REMOVEDIR) != 0 {
		return unix.Rmdir(path)
	} else {
		return unix.Unlink(path)
	}
}

// emulateMknodat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateMknodat(dirfd int, path string, mode uint32, dev int) error {
	if !filepath.IsAbs(path) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		cwd, err := unix.Open(".", unix.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer unix.Close(cwd)
		err = unix.Fchdir(dirfd)
		if err != nil {
			return err
		}
		defer unix.Fchdir(cwd)
	}
	return unix.Mknod(path, mode, dev)
}

// dirfdAbs transforms the dirfd-relative "path" to an absolute one. If the
// path is not already absolute, this function will change the working
// directory. The caller has to chdir back.
func dirfdAbs(dirfd int, path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	err := unix.Fchdir(dirfd)
	if err != nil {
		return "", err
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(wd, path), nil
}

// emulateFchmodat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateFchmodat(dirfd int, path string, mode uint32, flags int) (err error) {
	if !filepath.IsAbs(path) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		cwd, err := unix.Open(".", unix.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer unix.Close(cwd)
		err = unix.Fchdir(dirfd)
		if err != nil {
			return err
		}
		defer unix.Fchdir(cwd)
	}
	// We also don't have Lchmod, so emulate it (poorly).
	if flags&unix.AT_SYMLINK_NOFOLLOW != 0 {
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
	}
	return unix.Chmod(path, mode)
}

// emulateFchownat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateFchownat(dirfd int, path string, uid int, gid int, flags int) (err error) {
	if !filepath.IsAbs(path) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		cwd, err := unix.Open(".", unix.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer unix.Close(cwd)
		err = unix.Fchdir(dirfd)
		if err != nil {
			return err
		}
		defer unix.Fchdir(cwd)
	}
	return unix.Lchown(path, uid, gid)
}

// emulateSymlinkat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateSymlinkat(oldpath string, newdirfd int, newpath string) (err error) {
	if !filepath.IsAbs(newpath) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		cwd, err := unix.Open(".", unix.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer unix.Close(cwd)
		err = unix.Fchdir(newdirfd)
		if err != nil {
			return err
		}
		defer unix.Fchdir(cwd)
	}
	return unix.Symlink(oldpath, newpath)
}

// emulateMkdirat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateMkdirat(dirfd int, path string, mode uint32) (err error) {
	if !filepath.IsAbs(path) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		cwd, err := unix.Open(".", unix.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer unix.Close(cwd)
		err = unix.Fchdir(dirfd)
		if err != nil {
			return err
		}
		defer unix.Fchdir(cwd)
	}
	return unix.Mkdir(path, mode)
}

// emulateFstatat emulates the syscall for platforms that don't have it
// in the kernel (darwin).
func emulateFstatat(dirfd int, path string, stat *unix.Stat_t, flags int) (err error) {
	if !filepath.IsAbs(path) {
		chdirMutex.Lock()
		defer chdirMutex.Unlock()
		cwd, err := unix.Open(".", unix.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer unix.Close(cwd)
		err = unix.Fchdir(dirfd)
		if err != nil {
			return err
		}
		defer unix.Fchdir(cwd)
	}
	return unix.Lstat(path, stat)
}
