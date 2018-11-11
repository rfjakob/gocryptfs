// +build linux

// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"

	"github.com/pkg/xattr"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Only allow the "user" namespace, block "trusted" and "security", as
// these may be interpreted by the system, and we don't want to cause
// trouble with our encrypted garbage.
const xattrUserPrefix = "user."

func disallowedXAttrName(attr string) bool {
	return !strings.HasPrefix(attr, xattrUserPrefix)
}

func filterXattrSetFlags(flags int) int {
	return flags
}

// procFd returns the path to file descriptor "fd" in /proc/self/fd.
func procFd(fd int) string {
	return fmt.Sprintf("/proc/self/fd/%d", fd)
}

// getFileFd calls fs.Open() on relative plaintext path "relPath" and returns
// the resulting fusefrontend.*File along with the underlying fd. The caller
// MUST call file.Release() when done with the file.
//
// Used by xattrGet() and friends.
func (fs *FS) getFileFd(relPath string, context *fuse.Context) (*File, int, fuse.Status) {
	fuseFile, status := fs.Open(relPath, syscall.O_RDONLY, context)
	if !status.Ok() {
		return nil, -1, status
	}
	file, ok := fuseFile.(*File)
	if !ok {
		tlog.Warn.Printf("BUG: xattrGet: cast to *File failed")
		fuseFile.Release()
		return nil, -1, fuse.EIO
	}
	return file, file.intFd(), fuse.OK
}

// getXattr - read encrypted xattr name "cAttr" from relative
// plaintext path "relPath". Returns the encrypted xattr value.
//
// This function is symlink-safe by using /proc/self/fd.
func (fs *FS) getXattr(relPath string, cAttr string, context *fuse.Context) ([]byte, fuse.Status) {
	file, fd, status := fs.getFileFd(relPath, context)
	if !status.Ok() {
		return nil, status
	}
	defer file.Release()

	cData, err := xattr.Get(procFd(fd), cAttr)
	if err != nil {
		return nil, unpackXattrErr(err)
	}
	return cData, fuse.OK
}

// setXattr - set encrypted xattr name "cAttr" to value "cData" on plaintext
// path "relPath".
//
// This function is symlink-safe by using /proc/self/fd.
func (fs *FS) setXattr(relPath string, cAttr string, cData []byte, flags int, context *fuse.Context) fuse.Status {
	file, fd, status := fs.getFileFd(relPath, context)
	if !status.Ok() {
		return status
	}
	defer file.Release()

	err := xattr.SetWithFlags(procFd(fd), cAttr, cData, flags)
	return unpackXattrErr(err)
}

// removeXAttr - remove encrypted xattr name "cAttr" from
// plaintext path "relPath".
//
// This function is symlink-safe on Linux by using /proc/self/fd.
func (fs *FS) removeXAttr(relPath string, cAttr string, context *fuse.Context) fuse.Status {
	file, fd, status := fs.getFileFd(relPath, context)
	if !status.Ok() {
		return status
	}
	defer file.Release()

	err := xattr.Remove(procFd(fd), cAttr)
	return unpackXattrErr(err)
}
