package fusefrontend

import (
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
)

// openBackingDir opens the parent ciphertext directory of plaintext path
// "relPath". It returns the dirfd (opened with O_PATH) and the encrypted
// basename.
//
// The caller should then use Openat(dirfd, cName, ...) and friends.
// For convenience, if relPath is "", cName is going to be ".".
//
// openBackingDir is secure against symlink races by using Openat and
// ReadDirIVAt.
func (fs *FS) openBackingDir(relPath string) (dirfd int, cName string, err error) {
	dirRelPath := nametransform.Dir(relPath)
	// With PlaintextNames, we don't need to read DirIVs. Easy.
	if fs.args.PlaintextNames {
		dirfd, err = syscallcompat.OpenDirNofollow(fs.args.Cipherdir, dirRelPath)
		if err != nil {
			return -1, "", err
		}
		// If relPath is empty, cName is ".".
		cName = filepath.Base(relPath)
		return dirfd, cName, nil
	}
	// Cache lookup
	dirfd, iv := fs.dirCache.Lookup(dirRelPath)
	if dirfd > 0 {
		// If relPath is empty, cName is ".".
		if relPath == "" {
			return dirfd, ".", nil
		}
		name := filepath.Base(relPath)
		cName, err = fs.nameTransform.EncryptAndHashName(name, iv)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", err
		}
		return dirfd, cName, nil
	}
	// Open cipherdir (following symlinks)
	dirfd, err = syscall.Open(fs.args.Cipherdir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
	if err != nil {
		return -1, "", err
	}
	// If relPath is empty, cName is ".".
	if relPath == "" {
		return dirfd, ".", nil
	}
	// Walk the directory tree
	parts := strings.Split(relPath, "/")
	for i, name := range parts {
		iv, err := nametransform.ReadDirIVAt(dirfd)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", err
		}
		cName, err = fs.nameTransform.EncryptAndHashName(name, iv)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", err
		}
		// Last part? We are done.
		if i == len(parts)-1 {
			fs.dirCache.Store(dirRelPath, dirfd, iv)
			break
		}
		// Not the last part? Descend into next directory.
		dirfd2, err := syscallcompat.Openat(dirfd, cName, syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		syscall.Close(dirfd)
		if err != nil {
			return -1, "", err
		}
		dirfd = dirfd2
	}
	return dirfd, cName, nil
}
