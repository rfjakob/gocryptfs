package fusefrontend

import (
	"context"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/inomap"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
)

// Node is a file or directory in the filesystem tree
// in a gocryptfs mount.
type Node struct {
	fs.Inode
}

// RootNode is the root of the filesystem tree of Nodes.
type RootNode struct {
	Node
	// args stores configuration arguments
	args Args
	// Filename encryption helper
	nameTransform nametransform.NameTransformer
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// MitigatedCorruptions is used to report data corruption that is internally
	// mitigated by ignoring the corrupt item. For example, when OpenDir() finds
	// a corrupt filename, we still return the other valid filenames.
	// The corruption is logged to syslog to inform the user,	and in addition,
	// the corrupt filename is logged to this channel via
	// reportMitigatedCorruption().
	// "gocryptfs -fsck" reads from the channel to also catch these transparently-
	// mitigated corruptions.
	MitigatedCorruptions chan string
	// IsIdle flag is set to zero each time fs.isFiltered() is called
	// (uint32 so that it can be reset with CompareAndSwapUint32).
	// When -idle was used when mounting, idleMonitor() sets it to 1
	// periodically.
	IsIdle uint32

	// inoMap translates inode numbers from different devices to unique inode
	// numbers.
	inoMap *inomap.InoMap
}

func NewRootNode(args Args, c *contentenc.ContentEnc, n nametransform.NameTransformer) *RootNode {
	// TODO
	return &RootNode{
		args:          args,
		nameTransform: n,
		contentEnc:    c,
		inoMap:        inomap.New(),
	}
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
