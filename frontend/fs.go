package frontend

import (
	"fmt"
	"github.com/rfjakob/gocryptfs/cryptfs"
	"github.com/rfjakob/cluefs/lib/cluefs"
	fusefs "bazil.org/fuse/fs"
)

type FS struct {
	*cryptfs.CryptFS
	*cluefs.ClueFS
	backing string
}

type nullTracer struct {}

func (nullTracer) Trace(op cluefs.FsOperTracer) {}

func NewFS(key [16]byte, backing string) *FS {
	var nt nullTracer
	clfs, err := cluefs.NewClueFS(backing, nt)
	if err != nil {
		panic(err)
	}
	return &FS {
		CryptFS: cryptfs.NewCryptFS(key),
		ClueFS: clfs,
		backing: backing,
	}
}

func (fs *FS) Root() (fusefs.Node, error) {
	fmt.Printf("Root\n")
	return NewDir("", fs.backing, fs), nil
}
