package fusefrontend

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/inomap"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

var _ = (fs.NodeStatxer)((*Node)(nil))
var _ = (fs.FileStatxer)((*File)(nil))

// Statx is the Linux statx equivalent of Getattr.
func (n *Node) Statx(ctx context.Context, f fs.FileHandle, flags uint32, mask uint32, out *fuse.StatxOut) (errno syscall.Errno) {
	// If the kernel gives us a file handle, use it. Current Linux kernels do
	// not send one with FUSE_STATX, but keep this for future compatibility.
	if f != nil {
		if fsx, ok := f.(fs.FileStatxer); ok {
			return fsx.Statx(ctx, flags, mask, out)
		}
	}

	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return errno
	}
	defer syscall.Close(dirfd)

	var st unix.Statx_t
	err := syscallcompat.Statx(dirfd, cName, int(flags)|unix.AT_SYMLINK_NOFOLLOW, int(mask), &st)
	if err != nil {
		return fs.ToErrno(err)
	}

	// fix inode number, size, owner
	rn := n.rootNode()
	st.Ino = rn.inoMap.Translate(inomap.NewQIno(unix.Mkdev(st.Dev_major, st.Dev_minor), 0, st.Ino))
	st.Size = rn.translateSize(dirfd, cName, uint32(st.Mode), st.Size)
	if rn.args.ForceOwner != nil {
		st.Uid = rn.args.ForceOwner.Uid
		st.Gid = rn.args.ForceOwner.Gid
	}

	out.FromStatx(&st)
	return 0
}

// Statx returns statx information for an open backing file. Current Linux
// kernels do not send a file handle with FUSE_STATX, so this is not reached yet.
func (f *File) Statx(_ context.Context, flags uint32, mask uint32, out *fuse.StatxOut) syscall.Errno {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	var st unix.Statx_t
	err := syscallcompat.Statx(f.intFd(), "", int(flags)|unix.AT_EMPTY_PATH, int(mask), &st)
	if err != nil {
		return fs.ToErrno(err)
	}

	// fix inode number, size, owner
	rn := f.rootNode
	st.Ino = rn.inoMap.Translate(inomap.NewQIno(unix.Mkdev(st.Dev_major, st.Dev_minor), 0, st.Ino))
	if uint32(st.Mode)&syscall.S_IFMT == syscall.S_IFREG {
		st.Size = rn.contentEnc.CipherSizeToPlainSize(st.Size)
	}
	if rn.args.ForceOwner != nil {
		st.Uid = rn.args.ForceOwner.Uid
		st.Gid = rn.args.ForceOwner.Gid
	}

	out.FromStatx(&st)
	return 0
}
