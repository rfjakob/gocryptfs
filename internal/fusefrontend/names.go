package fusefrontend

// This file forwards file encryption operations to cryptfs

import (
	"os"
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
func (fs *FS) openBackingDir(relPath string) (*os.File, string, error) {
	cRelPath, err := fs.encryptPath(relPath)
	if err != nil {
		return nil, "", err
	}
	// Open parent dir
	dirfd, err := syscallcompat.OpenDirNofollow(fs.args.Cipherdir, filepath.Dir(cRelPath))
	if err != nil {
		return nil, "", err
	}
	return os.NewFile(uintptr(dirfd), cRelPath), filepath.Base(cRelPath), nil
}

// encryptPath - encrypt relative plaintext path
func (fs *FS) encryptPath(plainPath string) (string, error) {
	if fs.args.PlaintextNames {
		return plainPath, nil
	}
	fs.dirIVLock.RLock()
	cPath, err := fs.nameTransform.EncryptPathDirIV(plainPath, fs.args.Cipherdir)
	tlog.Debug.Printf("encryptPath '%s' -> '%s' (err: %v)", plainPath, cPath, err)
	fs.dirIVLock.RUnlock()
	return cPath, err
}
