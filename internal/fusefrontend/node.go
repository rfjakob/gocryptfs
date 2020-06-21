package fusefrontend

import (
	"context"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
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

func (n *Node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	rn := n.rootNode()
	p := filepath.Join(n.path(), name)
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
