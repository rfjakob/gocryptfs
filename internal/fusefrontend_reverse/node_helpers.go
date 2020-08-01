package fusefrontend_reverse

import (
	"context"
	"path/filepath"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// translateSize translates the ciphertext size in `out` into plaintext size.
func (n *Node) translateSize(dirfd int, cName string, out *fuse.Attr) {
	if out.IsRegular() {
		rn := n.rootNode()
		out.Size = rn.contentEnc.PlainSizeToCipherSize(out.Size)
	} else if out.IsSymlink() {
		panic("todo: call readlink once it is implemented")
	}
}

// Path returns the relative plaintext path of this node
func (n *Node) Path() string {
	return n.Inode.Path(n.Root())
}

// rootNode returns the Root Node of the filesystem.
func (n *Node) rootNode() *RootNode {
	return n.Root().Operations().(*RootNode)
}

// prepareAtSyscall returns a (dirfd, cName) pair that can be used
// with the "___at" family of system calls (openat, fstatat, unlinkat...) to
// access the backing encrypted directory.
//
// If you pass a `child` file name, the (dirfd, cName) pair will refer to
// a child of this node.
// If `child` is empty, the (dirfd, cName) pair refers to this node itself.
func (n *Node) prepareAtSyscall(child string) (dirfd int, cName string, errno syscall.Errno) {
	p := n.Path()
	if child != "" {
		p = filepath.Join(p, child)
	}
	rn := n.rootNode()
	dirfd, cName, err := rn.openBackingDir(p)
	if err != nil {
		errno = fs.ToErrno(err)
	}
	return
}

// newChild attaches a new child inode to n.
// The passed-in `st` will be modified to get a unique inode number.
func (n *Node) newChild(ctx context.Context, st *syscall.Stat_t, out *fuse.EntryOut) *fs.Inode {
	// Get unique inode number
	rn := n.rootNode()
	rn.inoMap.TranslateStat(st)
	out.Attr.FromStat(st)
	// Create child node
	id := fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  1,
		Ino:  st.Ino,
	}
	node := &Node{}
	return n.NewInode(ctx, node, id)
}

// isRoot returns true if this node is the root node
func (n *Node) isRoot() bool {
	rn := n.rootNode()
	return &rn.Node == n
}
