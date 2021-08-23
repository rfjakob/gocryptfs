package pathiv

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
)

// Purpose identifies for which purpose the IV will be used. This is mixed into the
// derivation.
type Purpose string

const (
	// PurposeDirIV means the value will be used as a directory IV
	PurposeDirIV Purpose = "DIRIV"
	// PurposeFileID means the value will be used as the file ID in the file header
	PurposeFileID Purpose = "FILEID"
	// PurposeSymlinkIV means the value will be used as the IV for symlink encryption
	PurposeSymlinkIV Purpose = "SYMLINKIV"
	// PurposeBlock0IV means the value will be used as the IV of ciphertext block #0.
	PurposeBlock0IV Purpose = "BLOCK0IV"
)

// Derive derives an IV from an encrypted path by hashing it with sha256
func Derive(path string, purpose Purpose) []byte {
	// Use null byte as separator as it cannot occur in the path
	extended := []byte(path + "\000" + string(purpose))
	hash := sha256.Sum256(extended)
	return hash[:nametransform.DirIVLen]
}

// FileIVs contains both IVs that are needed to create a file.
type FileIVs struct {
	ID       []byte
	Block0IV []byte
}

// DeriveFile derives both IVs that are needed to create a file and returns them
// in a container struct.
func DeriveFile(path string) (fileIVs FileIVs) {
	fileIVs.ID = Derive(path, PurposeFileID)
	fileIVs.Block0IV = Derive(path, PurposeBlock0IV)
	return fileIVs
}

// BlockIV returns the block IV for block number "blockNo". "block0iv" is the block
// IV of block #0.
func BlockIV(block0iv []byte, blockNo uint64) []byte {
	iv := make([]byte, len(block0iv))
	copy(iv, block0iv)
	// Add blockNo to one half of the iv
	lowBytes := iv[8:]
	lowInt := binary.BigEndian.Uint64(lowBytes)
	binary.BigEndian.PutUint64(lowBytes, lowInt+blockNo)
	return iv
}
