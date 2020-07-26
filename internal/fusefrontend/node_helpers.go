package fusefrontend

import (
	"context"
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
