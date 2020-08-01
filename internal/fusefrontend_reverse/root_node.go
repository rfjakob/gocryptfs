package fusefrontend_reverse

import (
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/inomap"
	"github.com/rfjakob/gocryptfs/internal/nametransform"

	"github.com/sabhiram/go-gitignore"
)

// RootNode is the root directory in a `gocryptfs -reverse` mount
type RootNode struct {
	Node
	// Stores configuration arguments
	args fusefrontend.Args
	// Filename encryption helper
	nameTransform nametransform.NameTransformer
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// Tests whether a path is excluded (hiden) from the user. Used by -exclude.
	excluder ignore.IgnoreParser
	// inoMap translates inode numbers from different devices to unique inode
	// numbers.
	inoMap *inomap.InoMap
}

// NewRootNode returns an encrypted FUSE overlay filesystem.
// In this case (reverse mode) the backing directory is plain-text and
// ReverseFS provides an encrypted view.
func NewRootNode(args fusefrontend.Args, c *contentenc.ContentEnc, n nametransform.NameTransformer) *RootNode {
	return &RootNode{
		args:          args,
		nameTransform: n,
		contentEnc:    c,
		inoMap:        inomap.New(),
		excluder:      prepareExcluder(args),
	}
}
