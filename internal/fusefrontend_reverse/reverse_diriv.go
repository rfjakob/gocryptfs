package fusefrontend_reverse

import (
	"crypto/sha256"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

// derivePathIV derives an IV from an encrypted path by hashing it
func derivePathIV(path string) []byte {
	hash := sha256.Sum256([]byte(path))
	return hash[:nametransform.DirIVLen]
}

func (rfs *reverseFS) newDirIVFile(cRelPath string) (nodefs.File, fuse.Status) {
	cDir := saneDir(cRelPath)
	absDir, err := rfs.abs(rfs.decryptPath(cDir))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	return rfs.NewVirtualFile(derivePathIV(cDir), absDir)
}
