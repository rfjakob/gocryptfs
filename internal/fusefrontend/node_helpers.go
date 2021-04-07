package fusefrontend

import (
	"context"
	"log"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
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
// If `child` is empty, the (dirfd, cName) pair refers to this node itself. For
// the root node, that means (dirfd, ".").
func (n *Node) prepareAtSyscall(child string) (dirfd int, cName string, errno syscall.Errno) {
	rn := n.rootNode()
	// all filesystem operations go through prepareAtSyscall(), so this is a
	// good place to reset the idle marker.
	atomic.StoreUint32(&rn.IsIdle, 0)

	// root node itself is special
	if child == "" && n.IsRoot() {
		var err error
		dirfd, cName, err = rn.openBackingDir("")
		if err != nil {
			errno = fs.ToErrno(err)
		}
		return
	}

	// normal node itself can be converted to child of parent node
	if child == "" {
		name, p1 := n.Parent()
		if p1 == nil || name == "" {
			return -1, "", syscall.ENOENT
		}
		p2 := toNode(p1.Operations())
		return p2.prepareAtSyscall(name)
	}

	// Cache lookup
	// TODO make it work for plaintextnames as well?
	cacheable := (!rn.args.PlaintextNames)
	if cacheable {
		var iv []byte
		dirfd, iv = rn.dirCache.Lookup(n)
		if dirfd > 0 {
			cName, err := rn.nameTransform.EncryptAndHashName(child, iv)
			if err != nil {
				return -1, "", fs.ToErrno(err)
			}
			return dirfd, cName, 0
		}
	}

	// Slowpath
	if child == "" {
		log.Panicf("BUG: child name is empty - this cannot happen")
	}
	p := filepath.Join(n.Path(), child)
	if rn.isFiltered(p) {
		errno = syscall.EPERM
		return
	}
	dirfd, cName, err := rn.openBackingDir(p)
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}

	// Cache store
	if cacheable {
		// TODO: openBackingDir already calls ReadDirIVAt(). Avoid duplicate work?
		iv, err := nametransform.ReadDirIVAt(dirfd)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", fs.ToErrno(err)
		}
		rn.dirCache.Store(n, dirfd, iv)
	}
	return
}

// newChild attaches a new child inode to n.
// The passed-in `st` will be modified to get a unique inode number
// (or, in `-sharedstorage` mode, the inode number will be set to zero).
func (n *Node) newChild(ctx context.Context, st *syscall.Stat_t, out *fuse.EntryOut) *fs.Inode {
	rn := n.rootNode()
	// Get stable inode number based on underlying (device,ino) pair
	// (or set to zero in case of `-sharestorage`)
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
