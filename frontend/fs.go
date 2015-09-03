package frontend

import (
	"github.com/rfjakob/gocryptfs/cryptfs"
	"bazil.org/fuse/fs"
)

type FS struct {
	*cryptfs.FS
}

func New(key [16]byte) *FS {
	return &FS {
		FS: cryptfs.NewFS(key),
	}
}

func (fs *FS) Root() (fs.Node, error) {
	return nil, nil
}
