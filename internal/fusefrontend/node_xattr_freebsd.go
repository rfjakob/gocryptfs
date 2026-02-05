package fusefrontend

import (
	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const noSuchAttributeError = unix.ENOATTR

func filterXattrSetFlags(flags int) int {
	return flags
}

func (n *Node) getXAttr(cAttr string) (out []byte, errno unix.Errno) {
	// TODO
	return nil, unix.EOPNOTSUPP
}

func (n *Node) setXAttr(context *fuse.Context, cAttr string, cData []byte, flags uint32) (errno unix.Errno) {
	// TODO
	return unix.EOPNOTSUPP
}

func (n *Node) removeXAttr(cAttr string) (errno unix.Errno) {
	// TODO
	return unix.EOPNOTSUPP
}

func (n *Node) listXAttr() (out []string, errno unix.Errno) {
	// TODO
	return nil, unix.EOPNOTSUPP
}
