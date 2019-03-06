// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

import (
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"

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
// This function is symlink-safe through Fgetxattr.
func (fs *FS) GetXAttr(relPath string, attr string, context *fuse.Context) ([]byte, fuse.Status) {
	if fs.isFiltered(relPath) {
		return nil, fuse.EPERM
	}
	if disallowedXAttrName(attr) {
		return nil, _EOPNOTSUPP
	}

	cAttr := fs.encryptXattrName(attr)

	cData, status := fs.getXAttr(relPath, cAttr, context)
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
// This function is symlink-safe through Fsetxattr.
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
	return fs.setXAttr(relPath, cAttr, cData, flags, context)
}

// RemoveXAttr - FUSE call.
//
// This function is symlink-safe through Fremovexattr.
func (fs *FS) RemoveXAttr(relPath string, attr string, context *fuse.Context) fuse.Status {
	if fs.isFiltered(relPath) {
		return fuse.EPERM
	}
	if disallowedXAttrName(attr) {
		return _EOPNOTSUPP
	}

	cAttr := fs.encryptXattrName(attr)
	return fs.removeXAttr(relPath, cAttr, context)
}

// ListXAttr - FUSE call. Lists extended attributes on the file at "relPath".
//
// This function is symlink-safe through Flistxattr.
func (fs *FS) ListXAttr(relPath string, context *fuse.Context) ([]string, fuse.Status) {
	if fs.isFiltered(relPath) {
		return nil, fuse.EPERM
	}

	cNames, status := fs.listXAttr(relPath, context)
	if !status.Ok() {
		return nil, status
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
	cData, err2 := fs.nameTransform.B64DecodeString(string(cData))
	if err2 != nil {
		// Looks like the value was not base64-encoded, but just corrupt.
		// Return the original decryption error: err1
		return nil, err1
	}
	return fs.contentEnc.DecryptBlock([]byte(cData), 0, nil)
}
