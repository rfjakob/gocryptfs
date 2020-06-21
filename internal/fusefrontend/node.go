package fusefrontend

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Node is a file or directory in the filesystem tree
// in a gocryptfs mount.
type Node struct {
	fs.Inode
}

// path returns the relative plaintext path of this node
func (n *Node) path() string {
	return n.Path(n.Root())
}

func (n *Node) rootNode() *RootNode {
	return n.Root().Operations().(*RootNode)
}

// Lookup - FUSE call for discovering a file.
func (n *Node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	rn := n.rootNode()
	p := filepath.Join(n.path(), name)
	if rn.isFiltered(p) {
		return nil, syscall.EPERM
	}
	dirfd, cName, err := rn.openBackingDir(p)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(dirfd)
	// Get device number and inode number into `st`
	st, err := syscallcompat.Fstatat2(dirfd, cName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	// Get unique inode number
	rn.inoMap.TranslateStat(st)
	out.Attr.FromStat(st)
	// Create child node
	id := fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  1,
		Ino:  st.Ino,
	}
	node := &Node{}
	ch := n.NewInode(ctx, node, id)
	return ch, 0
}

// GetAttr - FUSE call for stat()ing a file.
//
// GetAttr is symlink-safe through use of openBackingDir() and Fstatat().
func (n *Node) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	rn := n.rootNode()
	dirfd, cName, err := rn.openBackingDir(n.path())
	if err != nil {
		return fs.ToErrno(err)
	}
	defer syscall.Close(dirfd)

	st, err := syscallcompat.Fstatat2(dirfd, cName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return fs.ToErrno(err)
	}
	rn.inoMap.TranslateStat(st)
	out.Attr.FromStat(st)
	return 0
}

// Create - FUSE call. Creates a new file.
//
// Symlink-safe through the use of Openat().
func (n *Node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	rn := n.rootNode()
	path := filepath.Join(n.path(), name)
	if rn.isFiltered(path) {
		return nil, nil, 0, syscall.EPERM
	}
	dirfd, cName, err := rn.openBackingDir(path)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	defer syscall.Close(dirfd)

	fd := -1
	// Make sure context is nil if we don't want to preserve the owner
	if !rn.args.PreserveOwner {
		ctx = nil
	}
	newFlags := rn.mangleOpenFlags(flags)
	// Handle long file name
	if !rn.args.PlaintextNames && nametransform.IsLongContent(cName) {
		// Create ".name"
		err = rn.nameTransform.WriteLongNameAt(dirfd, cName, path)
		if err != nil {
			return nil, nil, 0, fs.ToErrno(err)
		}
		// Create content
		fd, err = syscallcompat.OpenatUserCtx(dirfd, cName, newFlags|syscall.O_CREAT|syscall.O_EXCL, mode, ctx)
		if err != nil {
			nametransform.DeleteLongNameAt(dirfd, cName)
		}
	} else {
		// Create content, normal (short) file name
		fd, err = syscallcompat.OpenatUserCtx(dirfd, cName, newFlags|syscall.O_CREAT|syscall.O_EXCL, mode, ctx)
	}
	if err != nil {
		// xfstests generic/488 triggers this
		if err == syscall.EMFILE {
			var lim syscall.Rlimit
			syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
			tlog.Warn.Printf("Create %q: too many open files. Current \"ulimit -n\": %d", cName, lim.Cur)
		}
		return nil, nil, 0, fs.ToErrno(err)
	}

	// Get device number and inode number into `st`
	st, err := syscallcompat.Fstatat2(dirfd, cName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	// Get unique inode number
	rn.inoMap.TranslateStat(st)
	out.Attr.FromStat(st)
	// Create child node
	id := fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  1,
		Ino:  st.Ino,
	}
	node := &Node{}
	ch := n.NewInode(ctx, node, id)

	f := os.NewFile(uintptr(fd), cName)
	return ch, NewFile2(f, rn, st), 0, 0
}

// Unlink - FUSE call. Delete a file.
//
// Symlink-safe through use of Unlinkat().
func (n *Node) Unlink(ctx context.Context, name string) syscall.Errno {
	rn := n.rootNode()
	p := filepath.Join(n.path(), name)
	if rn.isFiltered(p) {
		return syscall.EPERM
	}
	dirfd, cName, err := rn.openBackingDir(p)
	if err != nil {
		return fs.ToErrno(err)
	}
	defer syscall.Close(dirfd)
	// Delete content
	err = syscallcompat.Unlinkat(dirfd, cName, 0)
	if err != nil {
		return fs.ToErrno(err)
	}
	// Delete ".name" file
	if !rn.args.PlaintextNames && nametransform.IsLongContent(cName) {
		err = nametransform.DeleteLongNameAt(dirfd, cName)
		if err != nil {
			tlog.Warn.Printf("Unlink: could not delete .name file: %v", err)
		}
	}
	return fs.ToErrno(err)
}
