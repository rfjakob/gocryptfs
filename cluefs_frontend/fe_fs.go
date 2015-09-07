package cluefs_frontend

// frontend sits between FUSE and ClueFS
// and uses cryptfs for all crypto operations
//
//          cryptfs
//             ^
//             |
//             v
// FUSE <-> frontend <-> ClueFS
//
// This file handles just the root directory

import (
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

func NewFS(key [16]byte, backing string, useOpenssl bool) (*FS, error) {
	var tracer nullTracer
	clfs, err := cluefs.NewClueFS(backing, tracer)
	if err != nil {
		return nil, err
	}
	return &FS {
		CryptFS: cryptfs.NewCryptFS(key, useOpenssl),
		ClueFS: clfs,
		backing: backing,
	}, nil
}

func (fs *FS) Root() (fusefs.Node, error) {
	cryptfs.Debug.Printf("Root\n")
	return NewDir("", fs.backing, fs), nil
}
