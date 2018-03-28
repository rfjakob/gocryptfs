// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

// FUSE operations on paths

import (
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/pkg/xattr"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// xattr names are encrypted like file names, but with a fixed IV.
var xattrNameIV = []byte("xattr_name_iv_xx")

// Only allow the "user" namespace, block "trusted" and "security", as
// these may be interpreted by the system, and we don't want to cause
// trouble with our encrypted garbage.
var xattrUserPrefix = "user."

// We store encrypted xattrs under this prefix plus the base64-encoded
// encrypted original name.
var xattrStorePrefix = "user.gocryptfs."

// GetXAttr: read the value of extended attribute "attr".
// Implements pathfs.Filesystem.
func (fs *FS) GetXAttr(path string, attr string, context *fuse.Context) ([]byte, fuse.Status) {
	if fs.isFiltered(path) {
		return nil, fuse.EPERM
	}
	cAttr, err := fs.encryptXattrName(attr)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	cData64, err := xattr.Get(cPath, cAttr)
	if err != nil {
		return nil, unpackXattrErr(err)
	}
	// xattr data is decrypted like a symlink target
	data, err := fs.decryptSymlinkTarget(string(cData64))
	if err != nil {
		tlog.Warn.Printf("GetXAttr: %v", err)
		return nil, fuse.EIO
	}
	return []byte(data), fuse.OK
}

// SetXAttr implements pathfs.Filesystem.
func (fs *FS) SetXAttr(path string, attr string, data []byte, flags int, context *fuse.Context) fuse.Status {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	if flags != 0 {
		return fuse.EPERM
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	cAttr, err := fs.encryptXattrName(attr)
	if err != nil {
		return fuse.ToStatus(err)
	}
	// xattr data is encrypted like a symlink target
	cData64 := []byte(fs.encryptSymlinkTarget(string(data)))
	return unpackXattrErr(xattr.Set(cPath, cAttr, cData64))
}

// RemoveXAttr implements pathfs.Filesystem.
func (fs *FS) RemoveXAttr(path string, attr string, context *fuse.Context) fuse.Status {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	cAttr, err := fs.encryptXattrName(attr)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return unpackXattrErr(xattr.Remove(cPath, cAttr))
}

// ListXAttr implements pathfs.Filesystem.
func (fs *FS) ListXAttr(path string, context *fuse.Context) ([]string, fuse.Status) {
	if fs.isFiltered(path) {
		return nil, fuse.EPERM
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	cNames, err := xattr.List(cPath)
	if err != nil {
		return nil, unpackXattrErr(err)
	}
	names := make([]string, 0, len(cNames))
	for _, curName := range cNames {
		if !strings.HasPrefix(curName, xattrStorePrefix) {
			continue
		}
		name, err := fs.decryptXattrName(curName)
		if err != nil {
			tlog.Warn.Printf("ListXAttr: invalid xattr name %q: %v", curName, err)
			continue
		}
		names = append(names, name)
	}
	return names, fuse.OK
}

// encryptXattrName transforms "user.foo" to "user.gocryptfs.a5sAd4XAa47f5as6dAf"
func (fs *FS) encryptXattrName(attr string) (cAttr string, err error) {
	// Reject anything that does not start with "user."
	if !strings.HasPrefix(attr, xattrUserPrefix) {
		return "", syscall.EPERM
	}
	// xattr names are encrypted like file names, but with a fixed IV.
	cAttr = xattrStorePrefix + fs.nameTransform.EncryptName(attr, xattrNameIV)
	return cAttr, nil
}

func (fs *FS) decryptXattrName(cAttr string) (attr string, err error) {
	// Reject anything that does not start with "user.gocryptfs."
	if !strings.HasPrefix(cAttr, xattrStorePrefix) {
		return "", syscall.EINVAL
	}
	// Strip "user.gocryptfs." prefix
	cAttr = cAttr[len(xattrStorePrefix):]
	attr, err = fs.nameTransform.DecryptName(cAttr, xattrNameIV)
	if err != nil {
		return "", err
	}
	return attr, nil
}

// unpackXattrErr unpacks an error value that we got from xattr.Get/Set/etc
// and converts it to a fuse status.
func unpackXattrErr(err error) fuse.Status {
	if err == nil {
		return fuse.OK
	}
	err2, ok := err.(*xattr.Error)
	if !ok {
		tlog.Warn.Printf("unpackXattrErr: cannot unpack err=%v", err)
		return fuse.EIO
	}
	return fuse.ToStatus(err2.Err)
}
