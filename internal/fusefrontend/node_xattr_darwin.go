package fusefrontend

import (
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// On Darwin we have to unset XATTR_NOSECURITY 0x0008
func filterXattrSetFlags(flags int) int {
	// See https://opensource.apple.com/source/xnu/xnu-1504.15.3/bsd/sys/xattr.h.auto.html
	const XATTR_NOSECURITY = 0x0008

	return flags &^ XATTR_NOSECURITY
}

func (n *Node) getXAttr(cAttr string) (out []byte, errno syscall.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	// O_NONBLOCK to not block on FIFOs.
	fd, err := syscallcompat.Openat(dirfd, cName, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
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

func (n *Node) setXAttr(context *fuse.Context, cAttr string, cData []byte, flags uint32) (errno syscall.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	// O_NONBLOCK to not block on FIFOs.
	fd, err := syscallcompat.Openat(dirfd, cName, syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	// Directories cannot be opened read-write. Retry.
	if err == syscall.EISDIR {
		fd, err = syscallcompat.Openat(dirfd, cName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	}
	if err != nil {
		fs.ToErrno(err)
	}
	defer syscall.Close(fd)

	err = unix.Fsetxattr(fd, cAttr, cData, int(flags))
	return fs.ToErrno(err)
}

func (n *Node) removeXAttr(cAttr string) (errno syscall.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	// O_NONBLOCK to not block on FIFOs.
	fd, err := syscallcompat.Openat(dirfd, cName, syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	// Directories cannot be opened read-write. Retry.
	if err == syscall.EISDIR {
		fd, err = syscallcompat.Openat(dirfd, cName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	}
	if err != nil {
		return fs.ToErrno(err)
	}
	defer syscall.Close(fd)

	err = unix.Fremovexattr(fd, cAttr)
	return fs.ToErrno(err)
}

func (n *Node) listXAttr() (out []string, errno syscall.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	// O_NONBLOCK to not block on FIFOs.
	fd, err := syscallcompat.Openat(dirfd, cName, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(fd)

	cNames, err := syscallcompat.Flistxattr(fd)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return cNames, 0
}
