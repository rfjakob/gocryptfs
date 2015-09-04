package frontend

import (
	"github.com/rfjakob/gocryptfs/cryptfs"
	"github.com/rfjakob/cluefs/lib/cluefs"
)

type FS struct {
	*cryptfs.CryptFS
	*cluefs.ClueFS
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
	}
}
