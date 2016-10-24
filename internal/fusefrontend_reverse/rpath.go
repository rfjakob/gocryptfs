package fusefrontend_reverse

import (
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

// saneDir is like filepath.Dir but returns "" instead of "."
func saneDir(path string) string {
	d := filepath.Dir(path)
	if d == "." {
		return ""
	}
	return d
}

type ivPurposeType string

const (
	ivPurposeDirIV     ivPurposeType = "DIRIV"
	ivPurposeFileID    ivPurposeType = "FILEID"
	ivPurposeSymlinkIV ivPurposeType = "SYMLINKIV"
	ivPurposeBlock0IV  ivPurposeType = "BLOCK0IV"
)

// derivePathIV derives an IV from an encrypted path by hashing it with sha256
func derivePathIV(path string, purpose ivPurposeType) []byte {
	// Use null byte as separator as it cannot occur in the path
	extended := []byte(path + "\000" + string(purpose))
	hash := sha256.Sum256(extended)
	return hash[:nametransform.DirIVLen]
}

func (rfs *reverseFS) abs(relPath string, err error) (string, error) {
	if err != nil {
		return "", err
	}
	return filepath.Join(rfs.args.Cipherdir, relPath), nil
}

func (rfs *reverseFS) decryptPath(relPath string) (string, error) {
	if rfs.args.PlaintextNames || relPath == "" {
		return relPath, nil
	}
	var err error
	var transformedParts []string
	parts := strings.Split(relPath, "/")
	for i, part := range parts {
		// Start at the top and recurse
		currentDir := filepath.Join(parts[:i]...)
		nameType := nametransform.NameType(part)
		dirIV := derivePathIV(currentDir, ivPurposeDirIV)
		var transformedPart string
		if nameType == nametransform.LongNameNone {
			transformedPart, err = rfs.nameTransform.DecryptName(part, dirIV)
			if err != nil {
				// We get lots of decrypt requests for names like ".Trash" that
				// are invalid base64. Convert them to ENOENT so the correct
				// error gets returned to the user.
				if _, ok := err.(base64.CorruptInputError); ok {
					return "", syscall.ENOENT
				}
				// Stat attempts on the link target of encrypted symlinks.
				// These are always valid base64 but the length is not a
				// multiple of 16.
				if err == syscall.EINVAL {
					return "", syscall.ENOENT
				}
				return "", err
			}
		} else if nameType == nametransform.LongNameContent {
			transformedPart, err = rfs.findLongnameParent(currentDir, dirIV, part)
			if err != nil {
				return "", err
			}
		} else {
			panic("longname bug, .name files should have been handled earlier")
		}
		transformedParts = append(transformedParts, transformedPart)
	}
	return filepath.Join(transformedParts...), nil
}
