package fusefrontend_reverse

import (
	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

// RNode is a file or directory in the filesystem tree
// in a `gocryptfs -reverse` mount.
type RNode struct {
	fs.Inode
}

func NewRootNode(args fusefrontend.Args, c *contentenc.ContentEnc, n nametransform.NameTransformer) *RNode {
	// TODO
	return &RNode{}
}
