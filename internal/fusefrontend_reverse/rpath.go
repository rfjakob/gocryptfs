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

// abs basically returns storage dir + "/" + relPath.
// It takes an error parameter so it can directly wrap decryptPath like this:
// a, err := rfs.abs(rfs.decryptPath(relPath))
// abs never generates an error on its own. In other words, abs(p, nil) never
// fails.
func (rfs *ReverseFS) abs(relPath string, err error) (string, error) {
	if err != nil {
		return "", err
	}
	return filepath.Join(rfs.args.Cipherdir, relPath), nil
}

func (rfs *ReverseFS) rDecryptName(cName string, dirIV []byte, pDir string) (pName string, err error) {
	nameType := nametransform.NameType(cName)
	if nameType == nametransform.LongNameNone {
		pName, err = rfs.nameTransform.DecryptName(cName, dirIV)
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
		pName, err = rfs.findLongnameParent(pDir, dirIV, cName)
		if err != nil {
			return "", err
		}
	} else {
		// It makes no sense to decrypt a ".name" file. This is a virtual file
		// that has no representation in the plaintext filesystem. ".name"
		// files should have already been handled in virtualfile.go.
		tlog.Warn.Printf("rDecryptName: cannot decrypt virtual file %q", cName)
		return "", syscall.EINVAL
	}
	return pName, nil
}

func (rfs *ReverseFS) decryptPath(relPath string) (string, error) {
	if rfs.args.PlaintextNames || relPath == "" {
		return relPath, nil
	}
	// Check if the parent dir is in the cache
	cDir := saneDir(relPath)
	dirIV, pDir := rPathCache.lookup(cDir)
	if dirIV != nil {
		cName := filepath.Base(relPath)
		pName, err := rfs.rDecryptName(cName, dirIV, pDir)
		if err != nil {
			return "", err
		}
		return filepath.Join(pDir, pName), nil
	}
	parts := strings.Split(relPath, "/")
	var transformedParts []string
	for i := range parts {
		// Start at the top and recurse
		currentCipherDir := filepath.Join(parts[:i]...)
		currentPlainDir := filepath.Join(transformedParts[:i]...)
		dirIV = derivePathIV(currentCipherDir, ivPurposeDirIV)
		transformedPart, err := rfs.rDecryptName(parts[i], dirIV, currentPlainDir)
		if err != nil {
			return "", err
		}
		transformedParts = append(transformedParts, transformedPart)
	}
	pRelPath := filepath.Join(transformedParts...)
	rPathCache.store(cDir, dirIV, saneDir(pRelPath))
	return pRelPath, nil
}
