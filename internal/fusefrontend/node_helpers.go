package fusefrontend

import (
	"context"
	"path/filepath"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// toFuseCtx tries to extract a fuse.Context from a generic context.Context.
func toFuseCtx(ctx context.Context) (ctx2 *fuse.Context) {
	if ctx == nil {
		return nil
	}
	if caller, ok := fuse.FromContext(ctx); ok {
		ctx2 = &fuse.Context{
			Caller: *caller,
		}
	}
	return ctx2
}

// toNode casts a generic fs.InodeEmbedder into *Node. Also handles *RootNode
// by return rn.Node.
func toNode(op fs.InodeEmbedder) *Node {
	if r, ok := op.(*RootNode); ok {
		return &r.Node
	}
	return op.(*Node)
}

// readlink reads and decrypts a symlink. Used by Readlink, Getattr, Lookup.
func (n *Node) readlink(dirfd int, cName string) (out []byte, errno syscall.Errno) {
	cTarget, err := syscallcompat.Readlinkat(dirfd, cName)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	rn := n.rootNode()
	if rn.args.PlaintextNames {
		return []byte(cTarget), 0
	}
	// Symlinks are encrypted like file contents (GCM) and base64-encoded
	target, err := rn.decryptSymlinkTarget(cTarget)
	if err != nil {
		tlog.Warn.Printf("Readlink %q: decrypting target failed: %v", cName, err)
		return nil, syscall.EIO
	}
	return []byte(target), 0
}

// translateSize translates the ciphertext size in `out` into plaintext size.
func (n *Node) translateSize(dirfd int, cName string, out *fuse.Attr) {
	if out.IsRegular() {
		rn := n.rootNode()
		out.Size = rn.contentEnc.CipherSizeToPlainSize(out.Size)
	} else if out.IsSymlink() {
		target, _ := n.readlink(dirfd, cName)
		out.Size = uint64(len(target))
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
	if rn.isFiltered(p) {
		errno = syscall.EPERM
		return
	}
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
