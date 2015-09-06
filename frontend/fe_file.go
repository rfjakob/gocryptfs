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
// This file handles files access

import (
	"fmt"
	"github.com/rfjakob/gocryptfs/cryptfs"
	"github.com/rfjakob/cluefs/lib/cluefs"

	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	"golang.org/x/net/context"
)

func fixFlags(flags fuse.OpenFlags) (fuse.OpenFlags, bool) {
	cryptfs.Debug.Printf("fixFlags: Before: %s\n", flags.String())
	var writeOnly bool
	// We always need read access to do read-modify-write cycles
	if flags & fuse.OpenWriteOnly > 0 {
		flags = flags &^ fuse.OpenWriteOnly
		flags = flags | fuse.OpenReadWrite
		writeOnly = true
	}
	// We also cannot open the file in append mode, we need to seek back for RMW
	flags = flags &^ fuse.OpenAppend
	cryptfs.Debug.Printf("fixFlags: After: %s\n", flags.String())
	return flags, writeOnly
}

func max(x int, y int) int {
	if x > y {
		return x
	}
	return y
}

type File struct {
	*cluefs.File
	crfs *cryptfs.CryptFS
	// Remember if the file is supposed to be write-only
	writeOnly bool
}

func (f *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fusefs.Handle, error) {
	cryptfs.Debug.Printf("File.Open\n")

	req.Flags, f.writeOnly = fixFlags(req.Flags)

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

	fmt.Printf("Read: o=%d l=%d\n", req.Offset, req.Size)

	// Read the backing ciphertext in one go
	iblocks := f.crfs.SplitRange(uint64(req.Offset), uint64(req.Size))
	var cipherReq fuse.ReadRequest
	var cipherResp fuse.ReadResponse
	o, l := f.crfs.JoinCiphertextRange(iblocks)
	cipherResp.Data = make([]byte, int(l))
	cipherReq.Offset = int64(o)
	cipherReq.Size = int(l)
	cryptfs.Debug.Printf("Read: cipherReq o=%d l=%d\n", o, l)
	err := f.File.Read(ctx, &cipherReq, &cipherResp)
	if err != nil {
		return err
	}

	// Decrypt it
	plaintext, err := f.crfs.DecryptBlocks(cipherResp.Data)
	if err != nil {
		resp.Data = plaintext
		return err
	}
	// Crop down to relevant part
	resp.Data = f.crfs.CropPlaintext(plaintext, iblocks)

	return nil
}

func (f *File) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	cryptfs.Debug.Printf("File.Write\n")
	resp.Size = 0
	iblocks := f.crfs.SplitRange(uint64(req.Offset), uint64(len(req.Data)))
	var blockData []byte
	for _, ib := range iblocks {
		if ib.IsPartial() {
			// RMW
			cryptfs.Debug.Printf("RMW\n")
			blockData = make([]byte, f.crfs.PlainBS())
			var readReq fuse.ReadRequest
			var readResp fuse.ReadResponse
			o, l := ib.PlaintextRange()
			readReq.Offset = int64(o)
			readReq.Size = int(l)
			err := f.Read(ctx, &readReq, &readResp)
			if err != nil {
				return err
			}
			copy(blockData, readResp.Data)
			copy(blockData[ib.Offset:ib.Offset+ib.Length], req.Data)
			blockLen := max(len(readResp.Data), int(ib.Offset+ib.Length))
			blockData = blockData[0:blockLen]
		} else {
			blockData = req.Data[0:f.crfs.PlainBS()]
		}
		ciphertext := f.crfs.EncryptBlock(blockData)
		var partReq fuse.WriteRequest
		var partResp fuse.WriteResponse
		o, _ := ib.CiphertextRange()
		partReq.Data = ciphertext
		partReq.Offset = int64(o)
		err := f.File.Write(ctx, &partReq, &partResp)
		if err != nil {
			fmt.Printf("Write failure: %s\n", err.Error())
			return err
		}
		// Remove written data from the front of the request
		cryptfs.Debug.Printf("req.Data[%d:%d]\n", int(ib.Length), len(req.Data))
		req.Data = req.Data[int(ib.Length):len(req.Data)]
		resp.Size += int(ib.Length)
	}
	return nil
}

func (f *File) Attr(ctx context.Context, attr *fuse.Attr) error {
	cryptfs.Debug.Printf("Attr\n")
	err := f.File.Node.Attr(ctx, attr)
	if err != nil {
		return err
	}
	attr.Size = f.crfs.PlainSize(attr.Size)
	return nil
}
