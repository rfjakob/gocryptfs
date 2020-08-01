package fusefrontend_reverse

import (
	"github.com/hanwen/go-fuse/v2/fs"
)

// Node is a file or directory in the filesystem tree
// in a `gocryptfs -reverse` mount.
type Node struct {
	fs.Inode
}
