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

const _EOPNOTSUPP = fuse.Status(syscall.EOPNOTSUPP)

// xattr names are encrypted like file names, but with a fixed IV.
// Padded with "_xx" for length 16.
var xattrNameIV = []byte("xattr_name_iv_xx")

// We store encrypted xattrs under this prefix plus the base64-encoded
// encrypted original name.
var xattrStorePrefix = "user.gocryptfs."

// GetXAttr - FUSE call. Reads the value of extended attribute "attr".
//
// This function is symlink-safe on Linux.
// Darwin does not have fgetxattr(2) nor /proc/self/fd. How to implement this
// on Darwin in a symlink-safe way?
func (fs *FS) GetXAttr(relPath string, attr string, context *fuse.Context) ([]byte, fuse.Status) {
	if fs.isFiltered(relPath) {
		return nil, fuse.EPERM
	}
	if disallowedXAttrName(attr) {
		return nil, _EOPNOTSUPP
	}
	cAttr := fs.encryptXattrName(attr)
	cData, status := fs.getXattr(relPath, cAttr, context)
	if !status.Ok() {
		return nil, status
	}
	data, err := fs.decryptXattrValue(cData)
	if err != nil {
		tlog.Warn.Printf("GetXAttr: %v", err)
		return nil, fuse.EIO
	}
	return data, fuse.OK
}

// SetXAttr - FUSE call. Set extended attribute.
//
// This function is symlink-safe on Linux.
// Darwin does not have fsetxattr(2) nor /proc/self/fd. How to implement this
// on Darwin in a symlink-safe way?
func (fs *FS) SetXAttr(relPath string, attr string, data []byte, flags int, context *fuse.Context) fuse.Status {
	if fs.isFiltered(relPath) {
		return fuse.EPERM
	}
	if disallowedXAttrName(attr) {
		return _EOPNOTSUPP
	}
	flags = filterXattrSetFlags(flags)
	cAttr := fs.encryptXattrName(attr)
	cData := fs.encryptXattrValue(data)
	return fs.setXattr(relPath, cAttr, cData, flags, context)
}

// RemoveXAttr - FUSE call.
//
// TODO: Make symlink-safe. Blocker: package xattr does not provide
// fremovexattr(2).
func (fs *FS) RemoveXAttr(path string, attr string, context *fuse.Context) fuse.Status {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	if disallowedXAttrName(attr) {
		return _EOPNOTSUPP
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	cAttr := fs.encryptXattrName(attr)
	return unpackXattrErr(xattr.LRemove(cPath, cAttr))
}

// ListXAttr - FUSE call. Lists extended attributes on the file at "path".
//
// TODO: Make symlink-safe. Blocker: package xattr does not provide
// flistxattr(2).
func (fs *FS) ListXAttr(path string, context *fuse.Context) ([]string, fuse.Status) {
	if fs.isFiltered(path) {
		return nil, fuse.EPERM
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	cNames, err := xattr.LList(cPath)
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
			fs.reportMitigatedCorruption(curName)
			continue
		}
		names = append(names, name)
	}
	return names, fuse.OK
}

// encryptXattrName transforms "user.foo" to "user.gocryptfs.a5sAd4XAa47f5as6dAf"
func (fs *FS) encryptXattrName(attr string) (cAttr string) {
	// xattr names are encrypted like file names, but with a fixed IV.
	cAttr = xattrStorePrefix + fs.nameTransform.EncryptName(attr, xattrNameIV)
	return cAttr
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

// encryptXattrValue encrypts the xattr value "data".
// The data is encrypted like a file content block, but without binding it to
// a file location (block number and file id are set to zero).
// Special case: an empty value is encrypted to an empty value.
func (fs *FS) encryptXattrValue(data []byte) (cData []byte) {
	if len(data) == 0 {
		return []byte{}
	}
	return fs.contentEnc.EncryptBlock(data, 0, nil)
}

// decryptXattrValue decrypts the xattr value "cData".
func (fs *FS) decryptXattrValue(cData []byte) (data []byte, err error) {
	if len(cData) == 0 {
		return []byte{}, nil
	}
	data, err1 := fs.contentEnc.DecryptBlock([]byte(cData), 0, nil)
	if err1 == nil {
		return data, nil
	}
	// This backward compatibility is needed to support old
	// file systems having xattr values base64-encoded.
	cData, err2 := fs.nameTransform.B64.DecodeString(string(cData))
	if err2 != nil {
		// Looks like the value was not base64-encoded, but just corrupt.
		// Return the original decryption error: err1
		return nil, err1
	}
	return fs.contentEnc.DecryptBlock([]byte(cData), 0, nil)
}

// unpackXattrErr unpacks an error value that we got from xattr.LGet/LSet/etc
// and converts it to a fuse status. If err == nil, it returns fuse.OK.
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
