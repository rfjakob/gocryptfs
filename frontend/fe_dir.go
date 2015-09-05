package frontend

// frontend sits between FUSE and ClueFS
// and uses cryptfs for all crypto operations
//
//          cryptfs
//             ^
//             |
//             v
// FUSE <-> frontend <-> ClueFS
//
// This file handles directories

import (
	"fmt"
	"github.com/rfjakob/gocryptfs/cryptfs"
	"github.com/rfjakob/cluefs/lib/cluefs"
	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	"golang.org/x/net/context"
)

type Dir struct {
	*cluefs.Dir

	crfs *cryptfs.CryptFS
}

func NewDir(parent string, name string, fs *FS) *Dir {
	cryptfs.Debug.Printf("NewDir parent=%s name=%s\n", parent, name)
	return &Dir {
		Dir: cluefs.NewDir(parent, name, fs.ClueFS),
		crfs: fs.CryptFS,
	}
}

func (d *Dir) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fusefs.Handle, error) {
	cryptfs.Debug.Printf("Open\n")
	h, err := d.Dir.Open(ctx, req, resp)
	if err != nil {
		return nil, err
	}
	clueDir := h.(*cluefs.Dir)

	return &Dir {
		Dir: clueDir,
		crfs: d.crfs,
	}, nil
}

func (d *Dir) Lookup(ctx context.Context, req *fuse.LookupRequest, resp *fuse.LookupResponse) (fusefs.Node, error) {
	cryptfs.Debug.Printf("Lookup %s\n", req.Name)
	req.Name = d.crfs.EncryptPath(req.Name)
	node, err := d.Dir.Lookup(ctx, req, resp)
	if err != nil {
		return nil, err
	}
	clueDir, ok := node.(*cluefs.Dir)
	if ok {
		return &Dir {
			Dir: clueDir,
			crfs: d.crfs,
		}, nil
	} else {
		resp.Attr.Size = d.crfs.PlainSize(resp.Attr.Size)
		clueFile := node.(*cluefs.File)
		return &File {
			File: clueFile,
			crfs: d.crfs,
		}, nil
	}
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	cryptfs.Debug.Printf("ReadDirAll\n")
	entries, err := d.Dir.ReadDirAll(ctx)
	if err != nil {
		return nil, err
	}
	var decrypted []fuse.Dirent
	for _, e := range entries {
		if e.Name == "." || e.Name == ".." {
			decrypted = append(decrypted, e)
			continue
		}
		newName, err := d.crfs.DecryptPath(e.Name)
		if err != nil {
			fmt.Printf("ReadDirAll: Error decoding \"%s\": %s\n", e.Name, err.Error())
			continue
		}
		e.Name = newName
		decrypted = append(decrypted, e)
	}
	return decrypted, nil
}

func (d *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fusefs.Node, error) {
	cryptfs.Debug.Printf("Mkdir %s\n", req.Name)
	req.Name = d.crfs.EncryptPath(req.Name)
	n, err := d.Dir.Mkdir(ctx, req)
	if err != nil {
		return nil, err
	}
	clueDir := n.(*cluefs.Dir)
	return &Dir {
		Dir: clueDir,
		crfs: d.crfs,
	}, nil
}

func (d *Dir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
	cryptfs.Debug.Printf("Remove\n")
	req.Name = d.crfs.EncryptPath(req.Name)
	return d.Dir.Remove(ctx, req)
}

func (d *Dir) Create(ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (fusefs.Node, fusefs.Handle, error) {
	cryptfs.Debug.Printf("Create\n")
	req.Flags, _ = fixFlags(req.Flags)
	req.Name = d.crfs.EncryptPath(req.Name)
	n, _, err := d.Dir.Create(ctx, req, resp)
	if err != nil {
		return nil, nil, err
	}
	clueFile := n.(*cluefs.File)
	cryptFile := &File {
		File: clueFile,
		crfs: d.crfs,
	}
	return cryptFile, cryptFile, nil
}
