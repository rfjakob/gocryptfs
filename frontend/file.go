package frontend

import (
	"fmt"
	"github.com/rfjakob/gocryptfs/cryptfs"
	"github.com/rfjakob/cluefs/lib/cluefs"

	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	"golang.org/x/net/context"
)

type File struct {
	*cluefs.File
	crfs *cryptfs.CryptFS
}

func (f *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fusefs.Handle, error) {
	fmt.Printf("File.Open: f.crfs=%p\n", f.crfs)
	h, err := f.File.Open(ctx, req, resp)
	if err != nil {
		return nil, err
	}
	clueFile := h.(*cluefs.File)
	return &File {
		File: clueFile,
		crfs: f.crfs,
	}, nil
}

func (f *File) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	fmt.Printf("File.Read: f.crfs=%p\n", f.crfs)
	iblocks := f.crfs.SplitRange(req.Offset, int64(req.Size))
	for _, ib := range iblocks {
		var partReq fuse.ReadRequest
		var partResp fuse.ReadResponse
		o, l := ib.CiphertextRange()
		partReq.Size = int(l)
		partResp.Data = make([]byte, int(l))
		partReq.Offset = o
		err := f.File.Read(ctx, &partReq, &partResp)
		if err != nil {
			return err
		}
		plaintext, err := f.crfs.DecryptBlock(partResp.Data)
		if err != nil {
			fmt.Printf("Read: Block %d: %s\n", ib.BlockNo, err.Error())
			return err
		}
		plaintext = ib.CropBlock(partResp.Data)
		resp.Data = append(resp.Data, plaintext...)
	}
	return nil
}

func (f *File) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	iblocks := f.crfs.SplitRange(req.Offset, int64(len(req.Data)))
	iblocks = iblocks
	return nil
}
