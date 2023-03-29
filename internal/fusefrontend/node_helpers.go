package fusefrontend

import (
	"context"
	"sync/atomic"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
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
// Handles regular files & symlinks (and finds out what is what by looking at
// `out.Mode`).
func (n *Node) translateSize(dirfd int, cName string, out *fuse.Attr) {
	if out.IsRegular() {
		rn := n.rootNode()
		out.Size = rn.contentEnc.CipherSizeToPlainSize(out.Size)
	} else if out.IsSymlink() {
		// read and decrypt target
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

// newChild attaches a new child inode to n.
// The passed-in `st` will be modified to get a unique inode number
// (or, in `-sharedstorage` mode, the inode number will be set to zero).
func (n *Node) newChild(ctx context.Context, st *syscall.Stat_t, out *fuse.EntryOut) *fs.Inode {
	rn := n.rootNode()
	// Get stable inode number based on underlying (device,ino) pair
	rn.inoMap.TranslateStat(st)
	out.Attr.FromStat(st)

	var gen uint64 = 1
	if rn.args.SharedStorage || rn.quirks&syscallcompat.QuirkDuplicateIno1 != 0 {
		// Make each directory entry a unique node by using a unique generation
		// value - see the comment at RootNode.gen for details.
		gen = atomic.AddUint64(&rn.gen, 1)
	}

	// Create child node
	id := fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  gen,
		Ino:  st.Ino,
	}
	node := &Node{}
	return n.NewInode(ctx, node, id)
}
