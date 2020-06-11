package fusefrontend

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

// Node is a file or directory in the filesystem tree
// in a gocryptfs mount.
type Node struct {
	fs.Inode
}

// RootNode is the root of the filesystem tree of Nodes.
type RootNode struct {
	Node

	// This flag is set to zero each time fs.isFiltered() is called
	// (uint32 so that it can be reset with CompareAndSwapUint32).
	// When -idle was used when mounting, idleMonitor() sets it to 1
	// periodically.
	IsIdle uint32
}

func NewRootNode(args Args, c *contentenc.ContentEnc, n nametransform.NameTransformer) *RootNode {
	// TODO
	return &RootNode{}
}

func (n *Node) path() string {
	return n.Path(n.Root())
}

func (n *Node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, 1
}

func (n *Node) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	return 1
}

func (n *Node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	return nil, 1
}
