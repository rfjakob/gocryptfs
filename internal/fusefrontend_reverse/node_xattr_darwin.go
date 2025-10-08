package fusefrontend_reverse

import (
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

func (n *Node) getXAttr(cAttr string) (out []byte, errno syscall.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)

	// O_NONBLOCK to not block on FIFOs.
	fd, err := syscallcompat.Openat(d.dirfd, d.pName, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(fd)

	cData, err := syscallcompat.Fgetxattr(fd, cAttr)
	if err != nil {
		return nil, fs.ToErrno(err)
	}

	return cData, 0
}

func (n *Node) listXAttr() (out []string, errno syscall.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)

	// O_NONBLOCK to not block on FIFOs.
	fd, err := syscallcompat.Openat(d.dirfd, d.pName, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(fd)

	pNames, err := syscallcompat.Flistxattr(fd)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return pNames, 0
}
