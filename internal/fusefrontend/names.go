package fusefrontend

// This file forwards file encryption operations to cryptfs

import (
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// isFiltered - check if plaintext "path" should be forbidden
//
// Prevents name clashes with internal files when file names are not encrypted
func (fs *FS) isFiltered(path string) bool {
	if !fs.args.PlaintextNames {
		return false
	}
	// gocryptfs.conf in the root directory is forbidden
	if path == configfile.ConfDefaultName {
		tlog.Info.Printf("The name /%s is reserved when -plaintextnames is used\n",
			configfile.ConfDefaultName)
		return true
	}
	// Note: gocryptfs.diriv is NOT forbidden because diriv and plaintextnames
	// are exclusive
	return false
}

// GetBackingPath - get the absolute encrypted path of the backing file
// from the relative plaintext path "relPath"
func (fs *FS) getBackingPath(relPath string) (string, error) {
	cPath, err := fs.encryptPath(relPath)
	if err != nil {
		return "", err
	}
	cAbsPath := filepath.Join(fs.args.Cipherdir, cPath)
	tlog.Debug.Printf("getBackingPath: %s + %s -> %s", fs.args.Cipherdir, relPath, cAbsPath)
	return cAbsPath, nil
}

// openBackingDir opens the parent ciphertext directory of plaintext path
// "relPath" and returns the dirfd and the encrypted basename.
//
// The caller should then use Openat(dirfd, cName, ...) and friends.
// For convenience, if relPath is "", cName is going to be ".".
//
// openBackingDir is secure against symlink races by using Openat and
// ReadDirIVAt.
func (fs *FS) openBackingDir(relPath string) (dirfd int, cName string, err error) {
	// With PlaintextNames, we don't need to read DirIVs. Easy.
	if fs.args.PlaintextNames {
		dir := nametransform.Dir(relPath)
		dirfd, err = syscallcompat.OpenDirNofollow(fs.args.Cipherdir, dir)
		if err != nil {
			return -1, "", err
		}
		// If relPath is empty, cName is ".".
		cName = filepath.Base(relPath)
		return dirfd, cName, nil
	}
	// Open cipherdir (following symlinks)
	dirfd, err = syscall.Open(fs.args.Cipherdir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
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
			return -1, "", err
		}
		cName = fs.nameTransform.EncryptAndHashName(name, iv)
		// Last part? We are done.
		if i == len(parts)-1 {
			break
		}
		// Not the last part? Descend into next directory.
		dirfd2, err := syscallcompat.Openat(dirfd, cName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		syscall.Close(dirfd)
		if err != nil {
			return -1, "", err
		}
		dirfd = dirfd2
	}
	return dirfd, cName, nil
}

// encryptPath - encrypt relative plaintext path
func (fs *FS) encryptPath(plainPath string) (string, error) {
	if plainPath != "" { // Empty path gets encrypted all the time without actual file accesses.
		fs.AccessedSinceLastCheck = 1
	} else { // Empty string gets encrypted as empty string
		return plainPath, nil
	}
	if fs.args.PlaintextNames {
		return plainPath, nil
	}

	fs.dirIVLock.RLock()
	cPath, err := fs.nameTransform.EncryptPathDirIV(plainPath, fs.args.Cipherdir)
	tlog.Debug.Printf("encryptPath '%s' -> '%s' (err: %v)", plainPath, cPath, err)
	fs.dirIVLock.RUnlock()
	return cPath, err
}
