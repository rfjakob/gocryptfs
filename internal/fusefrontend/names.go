package fusefrontend

// This file forwards file encryption operations to cryptfs

import (
	"os"
	"path/filepath"

	"github.com/rfjakob/gocryptfs/internal/configfile"
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

// openBackingPath - get the absolute encrypted path of the backing file
// and open the corresponding directory
func (fs *FS) openBackingPath(relPath string) (*os.File, string, error) {
	cPath, err := fs.getBackingPath(relPath)
	if err != nil {
		return nil, "", err
	}
	dirfd, err := os.Open(filepath.Dir(cPath))
	if err != nil {
		return nil, "", err
	}
	return dirfd, filepath.Base(cPath), nil
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
