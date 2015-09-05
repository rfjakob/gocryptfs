package frontend

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
	fmt.Printf("NewDir parent=%s name=%s\n", parent, name)
	return &Dir {
		Dir: cluefs.NewDir(parent, name, fs.ClueFS),
		crfs: fs.CryptFS,
	}
}

func (d *Dir) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fusefs.Handle, error) {
	fmt.Printf("Open\n")
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
	fmt.Printf("Lookup %s\n", req.Name)
	req.Name = d.crfs.EncryptPath(req.Name)
	n, err := d.Dir.Lookup(ctx, req, resp)
	if err != nil {
		return nil, err
	}
	clueDir, ok := n.(*cluefs.Dir)
	if ok {
		return &Dir { Dir: clueDir }, nil
	} else {
		clueFile := n.(*cluefs.File)
		return &File { File: clueFile }, nil
	}
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	fmt.Printf("ReadDirAll\n")
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
	fmt.Printf("Mkdir %s\n", req.Name)
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
	fmt.Printf("Remove\n")
	req.Name = d.crfs.EncryptPath(req.Name)
	return d.Dir.Remove(ctx, req)
}

func (d *Dir) Create(ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (fusefs.Node, fusefs.Handle, error) {
	fmt.Printf("Create\n")
	req.Name = d.crfs.EncryptPath(req.Name)
	n, _, err := d.Dir.Create(ctx, req, resp)
	if err != nil {
		return nil, nil, err
	}
	clueFile := n.(*cluefs.File)
	cryptFile := &File {File: clueFile}
	return cryptFile, cryptFile, nil
}
