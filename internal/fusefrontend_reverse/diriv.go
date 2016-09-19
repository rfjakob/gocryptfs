package fusefrontend_reverse

import (
	"crypto/sha256"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

// deriveDirIV derives the DirIV from the directory path by simply hashing it
func deriveDirIV(dirPath string) []byte {
	hash := sha256.Sum256([]byte(dirPath))
	return hash[:nametransform.DirIVLen]
}

type dirIVFile struct {
	// Embed nodefs.defaultFile for a ENOSYS implementation of all methods
	nodefs.File
	// file content
	content []byte
}

func NewDirIVFile(dirPath string) (nodefs.File, fuse.Status) {
	return &dirIVFile{
		File:    nodefs.NewDefaultFile(),
		content: deriveDirIV(dirPath),
	}, fuse.OK
}

// Read - FUSE call
func (f *dirIVFile) Read(buf []byte, off int64) (resultData fuse.ReadResult, status fuse.Status) {
	if off >= int64(len(f.content)) {
		return nil, fuse.OK
	}
	end := int(off) + len(buf)
	if end > len(f.content) {
		end = len(f.content)
	}
	return fuse.ReadResultData(f.content[off:end]), fuse.OK
}
