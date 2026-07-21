package fusefrontend

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"

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

	rn := n.rootNode()
	var st unix.Statx_t
	var err error
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	// Match Getattr's handling of deleted fifos.
	if errno == syscall.ENOENT && n.StableAttr().Mode == syscall.S_IFIFO {
		out.Mask = unix.STATX_BASIC_STATS
		out.Mode = syscall.S_IFIFO
		out.Ino = n.StableAttr().Ino
		out.Blksize = 4096
		out.Gid = 65534
		out.Uid = 65534
		goto out
	}
	if errno != 0 {
		return errno
	}
	defer syscall.Close(dirfd)

	err = syscallcompat.Statx(dirfd, cName, int(flags)|unix.AT_SYMLINK_NOFOLLOW, int(mask), &st)
	if err != nil {
		return fs.ToErrno(err)
	}
	out.FromStatx(&st)

	// go-fuse also enforces the stable inode number in its bridge, but set it
	// here as well to mirror Getattr before returning to the bridge.
	out.Ino = n.StableAttr().Ino
	n.translateStatxSize(dirfd, cName, &out.Statx)

out:
	if rn.args.ForceOwner != nil {
		out.Uid = rn.args.ForceOwner.Uid
		out.Gid = rn.args.ForceOwner.Gid
	}
	return 0
}

// translateStatxSize translates ciphertext size to plaintext size.
func (n *Node) translateStatxSize(dirfd int, cName string, out *fuse.Statx) {
	switch uint32(out.Mode) & syscall.S_IFMT {
	case syscall.S_IFREG:
		out.Size = n.rootNode().contentEnc.CipherSizeToPlainSize(out.Size)
	case syscall.S_IFLNK:
		target, _ := n.readlink(dirfd, cName)
		out.Size = uint64(len(target))
	}
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
	out.FromStatx(&st)
	out.Ino = f.rootNode.inoMap.Translate(f.qIno)
	if uint32(out.Mode)&syscall.S_IFMT == syscall.S_IFREG {
		out.Size = f.rootNode.contentEnc.CipherSizeToPlainSize(out.Size)
	}
	if f.rootNode.args.ForceOwner != nil {
		out.Uid = f.rootNode.args.ForceOwner.Uid
		out.Gid = f.rootNode.args.ForceOwner.Gid
	}
	return 0
}
