package frontend

import (
	"github.com/rfjakob/gocryptfs/cryptfs"
	"bazil.org/fuse/fs"
)

type FS struct {
	*cryptfs.FS
	backing string
}

func New(key [16]byte, b string) *FS {
	return &FS {
		FS: cryptfs.NewFS(key),
		backing: b,
	}
}

func (fs *FS) Root() (fs.Node, error) {
	n := Node{
		backing: "",
		parentFS: fs,
	}
	return n, nil
}
