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

// This function is NOT symlink-safe because Darwin lacks fgetxattr().
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
