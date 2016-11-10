package fusefrontend_reverse

import (
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/tlog"
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

func (rfs *ReverseFS) abs(relPath string, err error) (string, error) {
	if err != nil {
		return "", err
	}
	return filepath.Join(rfs.args.Cipherdir, relPath), nil
}

func (rfs *ReverseFS) decryptPath(relPath string) (string, error) {
	if rfs.args.PlaintextNames || relPath == "" {
		return relPath, nil
	}
	var err error
	var transformedParts []string
	parts := strings.Split(relPath, "/")
	for i, part := range parts {
		// Start at the top and recurse
		currentCipherDir := filepath.Join(parts[:i]...)
		nameType := nametransform.NameType(part)
		dirIV := derivePathIV(currentCipherDir, ivPurposeDirIV)
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
			currentPlainDir := filepath.Join(transformedParts[:i]...)
			transformedPart, err = rfs.findLongnameParent(currentPlainDir, dirIV, part)
			if err != nil {
				return "", err
			}
		} else {
			// It makes no sense to decrypt a ".name" file
			tlog.Warn.Printf("decryptPath: tried to decrypt %q!? Returning EINVAL.", part)
			return "", syscall.EINVAL
		}
		transformedParts = append(transformedParts, transformedPart)
	}
	return filepath.Join(transformedParts...), nil
}
