package fusefrontend_reverse

import (
	"os"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

type reverseFS struct {
	// Embed pathfs.defaultFileSystem for a ENOSYS implementation of all methods
	pathfs.FileSystem
	// pathfs.loopbackFileSystem, see go-fuse/fuse/pathfs/loopback.go
	loopbackfs pathfs.FileSystem
	// Stores configuration arguments
	args fusefrontend.Args
	// Filename encryption helper
	nameTransform *nametransform.NameTransform
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
}

// Encrypted FUSE overlay filesystem
func NewFS(args fusefrontend.Args) *reverseFS {
	cryptoCore := cryptocore.New(args.Masterkey, args.OpenSSL, true)
	contentEnc := contentenc.New(cryptoCore, contentenc.DefaultBS)
	nameTransform := nametransform.New(cryptoCore, args.LongNames)

	return &reverseFS{
		// pathfs.defaultFileSystem returns ENOSYS for all operations
		FileSystem:    pathfs.NewDefaultFileSystem(),
		loopbackfs:    pathfs.NewLoopbackFileSystem(args.Cipherdir),
		args:          args,
		nameTransform: nameTransform,
		contentEnc:    contentEnc,
	}
}

func (rfs *reverseFS) GetAttr(relPath string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	if rfs.isFiltered(relPath) {
		return nil, fuse.EPERM
	}
	relPath, err := rfs.decryptPath(relPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	a, status := rfs.loopbackfs.GetAttr(relPath, context)
	if a == nil {
		return a, status
	}
	// Calculate encrypted file size
	if a.IsRegular() {
		a.Size = rfs.contentEnc.PlainSizeToCipherSize(a.Size)
	}
	return a, fuse.OK
}

func (rfs *reverseFS) Access(relPath string, mode uint32, context *fuse.Context) fuse.Status {
	if rfs.isFiltered(relPath) {
		return fuse.EPERM
	}
	cPath, err := rfs.abs(rfs.encryptPath(relPath))
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fuse.ToStatus(syscall.Access(cPath, mode))
}

func (rfs *reverseFS) Open(relPath string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	if rfs.isFiltered(relPath) {
		return nil, fuse.EPERM
	}
	absPath, err := rfs.abs(rfs.decryptPath(relPath))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	f, err := os.OpenFile(absPath, int(flags), 0666)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	return NewFile(f, rfs.contentEnc)
}

func (rfs *reverseFS) OpenDir(relPath string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	relPath, err := rfs.decryptPath(relPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Read plaintext dir
	entries, status := rfs.loopbackfs.OpenDir(relPath, context)
	if entries == nil {
		return nil, status
	}
	// Encrypt names
	for i := range entries {
		entries[i].Name, err = rfs.encryptPath(entries[i].Name)
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
	}
	return entries, fuse.OK
}
