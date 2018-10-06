package fusefrontend

// This file forwards file encryption operations to cryptfs

import (
	"path/filepath"

	"github.com/rfjakob/gocryptfs/internal/configfile"
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
// The caller should then use Openat(dirfd, cName, ...) and friends.
// openBackingDir is secure against symlink races.
func (fs *FS) openBackingDir(relPath string) (dirfd int, cName string, err error) {
	cRelPath, err := fs.encryptPath(relPath)
	if err != nil {
		return -1, "", err
	}
	// Open parent dir
	dirfd, err = syscallcompat.OpenDirNofollow(fs.args.Cipherdir, filepath.Dir(cRelPath))
	if err != nil {
		return -1, "", err
	}
	cName = filepath.Base(cRelPath)
	return dirfd, cName, nil
}

// encryptPath - encrypt relative plaintext path
func (fs *FS) encryptPath(plainPath string) (string, error) {
	if plainPath != "" {  // Empty path gets encrypted all the time without actual file accesses.
		fs.AccessedSinceLastCheck = true
	} else {  // Empty string gets encrypted as empty string
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
