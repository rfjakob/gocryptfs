// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

import (
	"bytes"
	"context"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// xattr names are encrypted like file names, but with a fixed IV.
// Padded with "_xx" for length 16.
var xattrNameIV = []byte("xattr_name_iv_xx")

// We store encrypted xattrs under this prefix plus the base64-encoded
// encrypted original name.
var xattrStorePrefix = "user.gocryptfs."

// We get one read of this xattr for each write -
// see https://github.com/rfjakob/gocryptfs/issues/515 for details.
var xattrCapability = "security.capability"

// GetXAttr - FUSE call. Reads the value of extended attribute "attr".
//
// This function is symlink-safe through Fgetxattr.
func (n *Node) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	rn := n.rootNode()
	// If we are not mounted with -suid, reading the capability xattr does not
	// make a lot of sense, so reject the request and gain a massive speedup.
	// See https://github.com/rfjakob/gocryptfs/issues/515 .
	if !rn.args.Suid && attr == xattrCapability {
		// Returning EOPNOTSUPP is what we did till
		// ca9e912a28b901387e1dbb85f6c531119f2d5ef2 "fusefrontend: drop xattr user namespace restriction"
		// and it did not cause trouble. Seems cleaner than saying ENODATA.
		return 0, syscall.EOPNOTSUPP
	}
	cAttr := rn.encryptXattrName(attr)
	cData, errno := n.getXAttr(cAttr)
	if errno != 0 {
		return 0, errno
	}
	data, err := rn.decryptXattrValue(cData)
	if err != nil {
		tlog.Warn.Printf("GetXAttr: %v", err)
		return ^uint32(0), syscall.EIO
	}
	l := copy(dest, data)
	return uint32(l), 0
}

// SetXAttr - FUSE call. Set extended attribute.
//
// This function is symlink-safe through Fsetxattr.
func (n *Node) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	rn := n.rootNode()
	flags = uint32(filterXattrSetFlags(int(flags)))
	cAttr := rn.encryptXattrName(attr)
	cData := rn.encryptXattrValue(data)
	return n.setXAttr(cAttr, cData, flags)
}

// RemoveXAttr - FUSE call.
//
// This function is symlink-safe through Fremovexattr.
func (n *Node) Removexattr(ctx context.Context, attr string) syscall.Errno {
	rn := n.rootNode()
	cAttr := rn.encryptXattrName(attr)
	return n.removeXAttr(cAttr)
}

// ListXAttr - FUSE call. Lists extended attributes on the file at "relPath".
//
// This function is symlink-safe through Flistxattr.
func (n *Node) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	cNames, errno := n.listXAttr()
	if errno != 0 {
		return 0, errno
	}
	rn := n.rootNode()
	var buf bytes.Buffer
	for _, curName := range cNames {
		if !strings.HasPrefix(curName, xattrStorePrefix) {
			continue
		}
		name, err := rn.decryptXattrName(curName)
		if err != nil {
			tlog.Warn.Printf("ListXAttr: invalid xattr name %q: %v", curName, err)
			rn.reportMitigatedCorruption(curName)
			continue
		}
		buf.WriteString(name + "\000")
	}
	if buf.Len() > len(dest) {
		return ^uint32(0), syscall.ERANGE
	}
	return uint32(copy(dest, buf.Bytes())), 0
}
