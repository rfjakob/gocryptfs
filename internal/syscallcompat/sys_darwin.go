package syscallcompat

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Sorry, fallocate is not available on OSX at all and
// fcntl F_PREALLOCATE is not accessible from Go.
// See https://github.com/rfjakob/gocryptfs/issues/18 if you want to help.
func EnospcPrealloc(fd int, off int64, len int64) error {
	return nil
}

// See above.
func Fallocate(fd int, mode uint32, off int64, len int64) error {
	return syscall.EOPNOTSUPP
}

var chdirMutex sync.Mutex

// Poor man's Openat
func Openat(dirfd int, path string, flags int, mode uint32) (int, error) {
	chdirMutex.Lock()
	defer chdirMutex.Unlock()
	if !filepath.IsAbs(path) {
		// Save the old working directory
		oldWd, err := os.Getwd()
		if err != nil {
			return -1, err
		}
		// Chdir to target directory
		err = syscall.Fchdir(dirfd)
		if err != nil {
			return -1, err
		}
		// Chdir back at the end
		defer os.Chdir(oldWd)
	}
	return syscall.Open(path, flags, mode)
}

// Poor man's Renameat
func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) error {
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
	return syscall.Rename(oldpath, newpath)
}

// Poor man's Unlinkat
func Unlinkat(dirfd int, path string) error {
	chdirMutex.Lock()
	defer chdirMutex.Unlock()
	if !filepath.IsAbs(path) {
		oldWd, err := os.Getwd()
		if err != nil {
			return err
		}
		defer os.Chdir(oldWd)
	}
	path, err := dirfdAbs(dirfd, path)
	if err != nil {
		return err
	}
	return syscall.Unlink(path)
}

// Poor man's Mknodat
func Mknodat(dirfd int, path string, mode uint32, dev int) error {
	chdirMutex.Lock()
	defer chdirMutex.Unlock()
	if !filepath.IsAbs(path) {
		oldWd, err := os.Getwd()
		if err != nil {
			return err
		}
		defer os.Chdir(oldWd)
	}
	path, err := dirfdAbs(dirfd, path)
	if err != nil {
		return err
	}
	return syscall.Mknod(path, mode, dev)
}

// dirfdAbs transforms the dirfd-relative "path" to an absolute one. If the
// path is not already absolute, this function will change the working
// directory. The caller has to chdir back.
func dirfdAbs(dirfd int, path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	err := syscall.Fchdir(dirfd)
	if err != nil {
		return "", err
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(wd, path), nil
}

// Dup3 is not available on Darwin, so we use Dup2 instead.
func Dup3(oldfd int, newfd int, flags int) (err error) {
	if flags != 0 {
		log.Panic("darwin does not support dup3 flags")
	}
	return syscall.Dup2(oldfd, newfd)
}
