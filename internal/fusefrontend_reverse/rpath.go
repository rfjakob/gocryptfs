package fusefrontend_reverse

import (
	"encoding/base64"
	"log"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/pathiv"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// rDecryptName decrypts the ciphertext name "cName", given the dirIV of the
// directory "cName" lies in. The relative plaintext path to the directory
// "pDir" is used if a "gocryptfs.longname.XYZ.name" must be resolved.
func (rfs *RootNode) rDecryptName(cName string, dirIV []byte, pDir string) (pName string, err error) {
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
		dirfd, err := syscallcompat.OpenDirNofollow(rfs.args.Cipherdir, filepath.Dir(pDir))
		if err != nil {
			return "", err
		}
		defer syscall.Close(dirfd)
		fd, err := syscallcompat.Openat(dirfd, filepath.Base(pDir), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return "", err
		}
		defer syscall.Close(fd)
		var errno syscall.Errno
		pName, _, errno = rfs.findLongnameParent(fd, dirIV, cName)
		if errno != 0 {
			return "", errno
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
func (rn *RootNode) decryptPath(cPath string) (string, error) {
	if rn.args.PlaintextNames || cPath == "" {
		return cPath, nil
	}
	parts := strings.Split(cPath, "/")
	var transformedParts []string
	for i := range parts {
		// Start at the top and recurse
		currentCipherDir := filepath.Join(parts[:i]...)
		currentPlainDir := filepath.Join(transformedParts[:i]...)
		dirIV := rn.deriveDirIV(currentCipherDir)
		transformedPart, err := rn.rDecryptName(parts[i], dirIV, currentPlainDir)
		if err != nil {
			return "", err
		}
		transformedParts = append(transformedParts, transformedPart)
	}
	pRelPath := filepath.Join(transformedParts...)
	return pRelPath, nil
}

// deriveDirIV wraps pathiv.Derive but takes DeterministicNames into account.
func (rn *RootNode) deriveDirIV(cPath string) []byte {
	if rn.args.PlaintextNames {
		log.Panic("BUG: deriveDirIV called but PlaintextNames is set")
	}
	if rn.args.DeterministicNames {
		return make([]byte, nametransform.DirIVLen)
	}
	return pathiv.Derive(cPath, pathiv.PurposeDirIV)
}

// openBackingDir receives an already decrypted relative path
// "pRelPath", opens the directory that contains the target file/dir
// and returns the fd to the directory and the decrypted name of the
// target file. The fd/name pair is intended for use with fchownat and
// friends.
func (rn *RootNode) openBackingDir(cPath string) (dirfd int, pPath string, err error) {
	defer func() {
		tlog.Debug.Printf("openBackingDir %q -> %d %q %v\n", cPath, dirfd, pPath, err)
	}()
	dirfd = -1
	pPath, err = rn.decryptPath(cPath)
	if err != nil {
		return
	}
	if rn.isExcludedPlain(pPath) {
		err = syscall.EPERM
		return
	}
	// Open directory, safe against symlink races
	pDir := filepath.Dir(pPath)
	dirfd, err = syscallcompat.OpenDirNofollow(rn.args.Cipherdir, pDir)
	if err != nil {
		return
	}
	return dirfd, pPath, nil
}
