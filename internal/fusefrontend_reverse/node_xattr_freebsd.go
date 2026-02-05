package fusefrontend_reverse

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

const noSuchAttributeError = unix.ENOATTR

func (n *Node) getXAttr(cAttr string) (out []byte, errno unix.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer unix.Close(d.dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", d.dirfd, d.pName)
	pData, err := syscallcompat.Lgetxattr(procPath, cAttr)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return pData, 0
}

func (n *Node) listXAttr() (out []string, errno unix.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer unix.Close(d.dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", d.dirfd, d.pName)
	pNames, err := syscallcompat.Llistxattr(procPath)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return pNames, 0
}
