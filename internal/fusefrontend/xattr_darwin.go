// +build darwin

// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

import (
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
)

// On Darwin it is needed to unset XATTR_NOSECURITY 0x0008
func filterXattrSetFlags(flags int) int {
	// See https://opensource.apple.com/source/xnu/xnu-1504.15.3/bsd/sys/xattr.h.auto.html
	const XATTR_NOSECURITY = 0x0008

	return flags &^ XATTR_NOSECURITY
}

func (fs *FS) getXAttr(relPath string, cAttr string, context *fuse.Context) ([]byte, fuse.Status) {
	// O_NONBLOCK to not block on FIFOs.
	fd, err := fs.openBackingFile(relPath, syscall.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	defer syscall.Close(fd)

	cData, err := syscallcompat.Fgetxattr(fd, cAttr)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}

	return cData, fuse.OK
}

func (fs *FS) setXAttr(relPath string, cAttr string, cData []byte, flags int, context *fuse.Context) fuse.Status {
	// O_NONBLOCK to not block on FIFOs.
	fd, err := fs.openBackingFile(relPath, syscall.O_WRONLY|syscall.O_NONBLOCK)
	// Directories cannot be opened read-write. Retry.
	if err == syscall.EISDIR {
		fd, err = fs.openBackingFile(relPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK)
	}
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(fd)

	err = unix.Fsetxattr(fd, cAttr, cData, flags)
	return fuse.ToStatus(err)
}

func (fs *FS) removeXAttr(relPath string, cAttr string, context *fuse.Context) fuse.Status {
	// O_NONBLOCK to not block on FIFOs.
	fd, err := fs.openBackingFile(relPath, syscall.O_WRONLY|syscall.O_NONBLOCK)
	// Directories cannot be opened read-write. Retry.
	if err == syscall.EISDIR {
		fd, err = fs.openBackingFile(relPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK)
	}
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(fd)

	err = unix.Fremovexattr(fd, cAttr)
	return fuse.ToStatus(err)
}

func (fs *FS) listXAttr(relPath string, context *fuse.Context) ([]string, fuse.Status) {
	// O_NONBLOCK to not block on FIFOs.
	fd, err := fs.openBackingFile(relPath, syscall.O_RDONLY|syscall.O_NONBLOCK)
	// On a symlink, openBackingFile fails with ELOOP. Let's pretend there
	// can be no xattrs on symlinks, and always return an empty result.
	if err == syscall.ELOOP {
		return nil, fuse.OK
	}
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	defer syscall.Close(fd)

	cNames, err := syscallcompat.Flistxattr(fd)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	return cNames, fuse.OK
}
