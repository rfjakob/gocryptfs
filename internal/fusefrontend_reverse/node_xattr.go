// Package fusefrontend_reverse interfaces directly with the go-fuse library.
package fusefrontend_reverse

import (
	"bytes"
	"context"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/pathiv"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// We store encrypted xattrs under this prefix plus the base64-encoded
// encrypted original name.
var xattrStorePrefix = "user.gocryptfs."

// isAcl returns true if the attribute name is for storing ACLs
//
// ACLs are passed through without encryption
func isAcl(attr string) bool {
	return attr == "system.posix_acl_access" || attr == "system.posix_acl_default"
}

// GetXAttr - FUSE call. Reads the value of extended attribute "attr".
//
// This function is symlink-safe through Fgetxattr.
func (n *Node) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	rn := n.rootNode()
	// If -noxattr is enabled, return ENOATTR for all getxattr calls
	if rn.args.NoXattr {
		return 0, noSuchAttributeError
	}
	var data []byte
	// ACLs are passed through without encryption
	if isAcl(attr) {
		var errno syscall.Errno
		data, errno = n.getXAttr(attr)
		if errno != 0 {
			return 0, errno
		}
	} else {
		pAttr, err := rn.decryptXattrName(attr)
		if err != nil {
			return 0, syscall.EINVAL
		}
		pData, errno := n.getXAttr(pAttr)
		if errno != 0 {
			return 0, errno
		}
		nonce := pathiv.Derive(n.Path()+"\000"+attr, pathiv.PurposeXattrIV)
		data = rn.encryptXattrValue(pData, nonce)
	}
	if len(dest) < len(data) {
		return uint32(len(data)), syscall.ERANGE
	}
	l := copy(dest, data)
	return uint32(l), 0
}

// ListXAttr - FUSE call. Lists extended attributes on the file at "relPath".
//
// This function is symlink-safe through Flistxattr.
func (n *Node) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	rn := n.rootNode()
	// If -noxattr is enabled, return zero results for listxattr
	if rn.args.NoXattr {
		return 0, 0
	}
	// Can use dest as a temporary buffer
	sz, errno := n.listXAttr(dest)
	if errno != 0 {
		return 0, errno
	}
	// If dest empty, return the required size
	if len(dest) == 0 {
		// Asssume ciphertext expansion by a factor of 2
		// TODO: double-check max expansion factor
		return uint32(sz * 2), 0
	}
	pNames := syscallcompat.ParseListxattrBlob(dest[:sz])
	var buf bytes.Buffer
	for _, pName := range pNames {
		// ACLs are passed through without encryption
		if isAcl(pName) {
			buf.WriteString(pName + "\000")
			continue
		}
		cName, err := rn.encryptXattrName(pName)
		if err != nil {
			continue
		}
		buf.WriteString(cName + "\000")
	}
	if buf.Len() > len(dest) {
		return uint32(buf.Len()), syscall.ERANGE
	}
	return uint32(copy(dest, buf.Bytes())), 0
}
