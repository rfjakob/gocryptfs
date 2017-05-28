package pathiv

import (
	"crypto/sha256"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

type Purpose string

const (
	PurposeDirIV     Purpose = "DIRIV"
	PurposeFileID    Purpose = "FILEID"
	PurposeSymlinkIV Purpose = "SYMLINKIV"
	PurposeBlock0IV  Purpose = "BLOCK0IV"
)

// Derive derives an IV from an encrypted path by hashing it with sha256
func Derive(path string, purpose Purpose) []byte {
	// Use null byte as separator as it cannot occur in the path
	extended := []byte(path + "\000" + string(purpose))
	hash := sha256.Sum256(extended)
	return hash[:nametransform.DirIVLen]
}
