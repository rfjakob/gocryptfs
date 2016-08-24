package fusefrontend_reverse

import (
	"os"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

type FS struct {
	// loopbackFileSystem, see go-fuse/fuse/pathfs/loopback.go
	pathfs.FileSystem
	// Stores configuration arguments
	args fusefrontend.Args
	// Filename encryption helper
	nameTransform *nametransform.NameTransform
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
}

// Encrypted FUSE overlay filesystem
func NewFS(args fusefrontend.Args) *FS {
	cryptoCore := cryptocore.New(args.Masterkey, args.OpenSSL, true)
	contentEnc := contentenc.New(cryptoCore, contentenc.DefaultBS)
	nameTransform := nametransform.New(cryptoCore, args.LongNames)

	return &FS{
		FileSystem:    pathfs.NewLoopbackFileSystem(args.Cipherdir),
		args:          args,
		nameTransform: nameTransform,
		contentEnc:    contentEnc,
	}
}

func (fs *FS) GetAttr(relPath string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	if fs.isFiltered(relPath) {
		return nil, fuse.EPERM
	}
	relPath, err := fs.decryptPath(relPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	a, status := fs.FileSystem.GetAttr(relPath, context)
	if a == nil {
		return a, status
	}
	// Calculate encrypted file size
	if a.IsRegular() {
		a.Size = fs.contentEnc.PlainSizeToCipherSize(a.Size)
	}
	return a, fuse.OK
}

func (fs *FS) Open(relPath string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	if fs.isFiltered(relPath) {
		return nil, fuse.EPERM
	}
	absPath, err := fs.abs(fs.decryptPath(relPath))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	f, err := os.OpenFile(absPath, int(flags), 0666)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	return NewFile(f, fs.contentEnc)
}

func (fs *FS) OpenDir(relPath string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	relPath, err := fs.decryptPath(relPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Read plaintext dir
	entries, status := fs.FileSystem.OpenDir(relPath, context)
	if entries == nil {
		return nil, status
	}
	// Encrypt names
	for i := range entries {
		entries[i].Name, err = fs.encryptPath(entries[i].Name)
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
	}
	return entries, fuse.OK
}
