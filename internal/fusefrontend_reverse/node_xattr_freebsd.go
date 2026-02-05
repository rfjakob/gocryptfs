package fusefrontend_reverse

import (
	"golang.org/x/sys/unix"
)

const noSuchAttributeError = unix.ENOATTR

func (n *Node) getXAttr(cAttr string) (out []byte, errno unix.Errno) {
	// TODO
	return nil, unix.EOPNOTSUPP
}

func (n *Node) listXAttr() (out []string, errno unix.Errno) {
	// TODO
	return nil, unix.EOPNOTSUPP
}
