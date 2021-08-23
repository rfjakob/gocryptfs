package fusefrontend

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

func filterXattrSetFlags(flags int) int {
	return flags
}

func (n *Node) getXAttr(cAttr string) (out []byte, errno syscall.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, cName)
	cData, err := syscallcompat.Lgetxattr(procPath, cAttr)
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

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, cName)

	return fs.ToErrno(syscallcompat.LsetxattrUser(procPath, cAttr, cData, int(flags), context))
}

func (n *Node) removeXAttr(cAttr string) (errno syscall.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, cName)
	return fs.ToErrno(unix.Lremovexattr(procPath, cAttr))
}

func (n *Node) listXAttr() (out []string, errno syscall.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	procPath := fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, cName)
	cNames, err := syscallcompat.Llistxattr(procPath)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return cNames, 0
}
