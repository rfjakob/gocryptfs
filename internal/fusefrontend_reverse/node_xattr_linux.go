package fusefrontend_reverse

import (
	"fmt"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// On Linux, ENODATA is returned when an attribute is not found.
const noSuchAttributeError = syscall.ENODATA

func (n *Node) getXAttr(cAttr string) (out []byte, errno syscall.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", d.dirfd, d.pName)
	pData, err := syscallcompat.Lgetxattr(procPath, cAttr)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return pData, 0
}

func (n *Node) listXAttr(buf []byte) (sz int, errno syscall.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", d.dirfd, d.pName)
	sz, err := unix.Llistxattr(procPath, buf)
	return sz, fs.ToErrno(err)
}
