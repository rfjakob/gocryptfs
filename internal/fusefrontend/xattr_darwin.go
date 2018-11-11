// +build darwin

// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

import (
	"github.com/pkg/xattr"

	"github.com/hanwen/go-fuse/fuse"
)

func disallowedXAttrName(attr string) bool {
	return false
}

// On Darwin it is needed to unset XATTR_NOSECURITY 0x0008
func filterXattrSetFlags(flags int) int {
	return flags &^ xattr.XATTR_NOSECURITY
}

// This function is NOT symlink-safe because Darwin lacks
// both fgetxattr() and /proc/self/fd.
func (fs *FS) getXattr(relPath string, cAttr string, context *fuse.Context) ([]byte, fuse.Status) {
	cPath, err := fs.getBackingPath(relPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	cData, err := xattr.LGet(cPath, cAttr)
	if err != nil {
		return nil, unpackXattrErr(err)
	}
	return cData, fuse.OK
}

// This function is NOT symlink-safe because Darwin lacks
// both fsetxattr() and /proc/self/fd.
func (fs *FS) setXattr(relPath string, cAttr string, cData []byte, flags int, context *fuse.Context) fuse.Status {
	cPath, err := fs.getBackingPath(relPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	err = xattr.LSetWithFlags(cPath, cAttr, cData, flags)
	return unpackXattrErr(err)
}

// This function is NOT symlink-safe because Darwin lacks
// both fremovexattr() and /proc/self/fd.
func (fs *FS) removeXAttr(relPath string, cAttr string, context *fuse.Context) fuse.Status {
	cPath, err := fs.getBackingPath(relPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	err = xattr.LRemove(cPath, cAttr)
	return unpackXattrErr(err)
}

// This function is NOT symlink-safe because Darwin lacks
// both flistxattr() and /proc/self/fd.
func (fs *FS) listXAttr(relPath string, context *fuse.Context) ([]string, fuse.Status) {
	cPath, err := fs.getBackingPath(relPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	cNames, err := xattr.LList(cPath)
	if err != nil {
		return nil, unpackXattrErr(err)
	}
	return cNames, fuse.OK
}
