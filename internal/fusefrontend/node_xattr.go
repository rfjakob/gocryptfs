// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

import (
	"bytes"
	"context"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// -1 as uint32
const minus1 = ^uint32(0)

// We store encrypted xattrs under this prefix plus the base64-encoded
// encrypted original name.
var xattrStorePrefix = "user.gocryptfs."

// We get one read of this xattr for each write -
// see https://github.com/rfjakob/gocryptfs/issues/515 for details.
var xattrCapability = "security.capability"

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
	// If we are not mounted with -suid, reading the capability xattr does not
	// make a lot of sense, so reject the request and gain a massive speedup.
	// See https://github.com/rfjakob/gocryptfs/issues/515 .
	if !rn.args.Suid && attr == xattrCapability {
		// Returning EOPNOTSUPP is what we did till
		// ca9e912a28b901387e1dbb85f6c531119f2d5ef2 "fusefrontend: drop xattr user namespace restriction"
		// and it did not cause trouble. Seems cleaner than saying ENODATA.
		return 0, syscall.EOPNOTSUPP
	}
	var data []byte
	// ACLs are passed through without encryption
	if isAcl(attr) {
		var errno syscall.Errno
		data, errno = n.getXAttr(attr)
		if errno != 0 {
			return minus1, errno
		}
	} else {
		// encrypted user xattr
		cAttr, err := rn.encryptXattrName(attr)
		if err != nil {
			return minus1, syscall.EIO
		}
		cData, errno := n.getXAttr(cAttr)
		if errno != 0 {
			return 0, errno
		}
		data, err = rn.decryptXattrValue(cData)
		if err != nil {
			tlog.Warn.Printf("GetXAttr: %v", err)
			return minus1, syscall.EIO
		}
	}
	// Caller passes size zero to find out how large their buffer should be
	if len(dest) == 0 {
		return uint32(len(data)), 0
	}
	if len(dest) < len(data) {
		return minus1, syscall.ERANGE
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

	// ACLs are passed through without encryption
	if isAcl(attr) {
		// result of setting an acl depends on the user doing it
		var context *fuse.Context
		if rn.args.PreserveOwner {
			context = toFuseCtx(ctx)
		}
		return n.setXAttr(context, attr, data, flags)
	}

	cAttr, err := rn.encryptXattrName(attr)
	if err != nil {
		return syscall.EINVAL
	}
	cData := rn.encryptXattrValue(data)
	return n.setXAttr(nil, cAttr, cData, flags)
}

// RemoveXAttr - FUSE call.
//
// This function is symlink-safe through Fremovexattr.
func (n *Node) Removexattr(ctx context.Context, attr string) syscall.Errno {
	rn := n.rootNode()

	// ACLs are passed through without encryption
	if isAcl(attr) {
		return n.removeXAttr(attr)
	}

	cAttr, err := rn.encryptXattrName(attr)
	if err != nil {
		return syscall.EINVAL
	}
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
		// ACLs are passed through without encryption
		if isAcl(curName) {
			buf.WriteString(curName + "\000")
			continue
		}
		if !strings.HasPrefix(curName, xattrStorePrefix) {
			continue
		}
		name, err := rn.decryptXattrName(curName)
		if err != nil {
			tlog.Warn.Printf("ListXAttr: invalid xattr name %q: %v", curName, err)
			rn.reportMitigatedCorruption(curName)
			continue
		}
		// We *used to* encrypt ACLs, which caused a lot of problems.
		if isAcl(name) {
			tlog.Warn.Printf("ListXAttr: ignoring deprecated encrypted ACL %q = %q", curName, name)
			rn.reportMitigatedCorruption(curName)
			continue
		}
		buf.WriteString(name + "\000")
	}
	// Caller passes size zero to find out how large their buffer should be
	if len(dest) == 0 {
		return uint32(buf.Len()), 0
	}
	if buf.Len() > len(dest) {
		return minus1, syscall.ERANGE
	}
	return uint32(copy(dest, buf.Bytes())), 0
}
