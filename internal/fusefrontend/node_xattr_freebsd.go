package fusefrontend

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// On FreeBSD, ENODATA is returned when an attribute is not found.
const noSuchAttributeError = unix.ENOATTR

func filterXattrSetFlags(flags int) int {
	return flags
}

func (n *Node) getXAttr(cAttr string) (out []byte, errno unix.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer unix.Close(dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, cName)
	cData, err := syscallcompat.Lgetxattr(procPath, cAttr)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return cData, 0
}

func (n *Node) setXAttr(context *fuse.Context, cAttr string, cData []byte, flags uint32) (errno unix.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer unix.Close(dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, cName)

	return fs.ToErrno(syscallcompat.LsetxattrUser(procPath, cAttr, cData, int(flags), context))
}

func (n *Node) removeXAttr(cAttr string) (errno unix.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer unix.Close(dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, cName)
	return fs.ToErrno(unix.Lremovexattr(procPath, cAttr))
}

func (n *Node) listXAttr() (out []string, errno unix.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer unix.Close(dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, cName)
	cNames, err := syscallcompat.Llistxattr(procPath)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return cNames, 0
}
