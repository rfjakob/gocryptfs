package fusefrontend_reverse

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

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

// rDecryptName decrypts the ciphertext name "cName", given the dirIV of the
// directory "cName" lies in. The relative plaintext path to the directory
// "pDir" is used if a "gocryptfs.longname.XYZ.name" must be resolved.
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
			if err == syscall.EBADMSG {
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

// decryptPath decrypts a relative ciphertext path to a relative plaintext
// path.
func (rfs *ReverseFS) decryptPath(relPath string) (string, error) {
	if rfs.args.PlaintextNames || relPath == "" {
		return relPath, nil
	}
	// Check if the parent dir is in the cache
	cDir := nametransform.Dir(relPath)
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
		dirIV = pathiv.Derive(currentCipherDir, pathiv.PurposeDirIV)
		transformedPart, err := rfs.rDecryptName(parts[i], dirIV, currentPlainDir)
		if err != nil {
			return "", err
		}
		transformedParts = append(transformedParts, transformedPart)
	}
	pRelPath := filepath.Join(transformedParts...)
	rPathCache.store(cDir, dirIV, nametransform.Dir(pRelPath))
	return pRelPath, nil
}

// openBackingDir receives an already decrypted relative path
// "pRelPath", opens the directory that contains the target file/dir
// and returns the fd to the directory and the decrypted name of the
// target file. The fd/name pair is intended for use with fchownat and
// friends.
func (rfs *ReverseFS) openBackingDir(pRelPath string) (dirfd int, pName string, err error) {
	// Open directory, safe against symlink races
	pDir := filepath.Dir(pRelPath)
	dirfd, err = syscallcompat.OpenDirNofollow(rfs.args.Cipherdir, pDir)
	if err != nil {
		return -1, "", err
	}
	pName = filepath.Base(pRelPath)
	return dirfd, pName, nil
}
