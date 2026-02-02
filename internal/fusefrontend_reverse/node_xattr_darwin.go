package fusefrontend_reverse

import (
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// On Darwin, ENOATTR is returned when an attribute is not found.
const noSuchAttributeError = syscall.ENOATTR

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

func (n *Node) listXAttr(buf []byte) (sz int, errno syscall.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)

	// O_NONBLOCK to not block on FIFOs.
	fd, err := syscallcompat.Openat(d.dirfd, d.pName, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	defer syscall.Close(fd)

	sz, err = unix.Flistxattr(fd, buf)
	return sz, fs.ToErrno(err)
}
