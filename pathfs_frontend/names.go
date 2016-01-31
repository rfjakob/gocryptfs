package pathfs_frontend

// This file forwards file encryption operations to cryptfs

import (
	"github.com/rfjakob/gocryptfs/cryptfs"
)

// isFiltered - check if plaintext "path" should be forbidden
//
// Prevents name clashes with internal files when file names are not encrypted
func (fs *FS) isFiltered(path string) bool {
	if !fs.args.PlaintextNames {
		return false
	}
	// gocryptfs.conf in the root directory is forbidden
	if path == cryptfs.ConfDefaultName {
		cryptfs.Info.Printf("The name /%s is reserved when -plaintextnames is used\n",
			cryptfs.ConfDefaultName)
		return true
	}
	// Note: gocryptfs.diriv is NOT forbidden because diriv and plaintextnames
	// are exclusive
	return false
}

// encryptPath - encrypt relative plaintext path
func (fs *FS) encryptPath(plainPath string) (string, error) {
	if fs.args.PlaintextNames {
		return plainPath, nil
	}
	if !fs.args.DirIV {
		return fs.CryptFS.EncryptPathNoIV(plainPath), nil
	}
	fs.dirIVLock.RLock()
	defer fs.dirIVLock.RUnlock()
	return fs.CryptFS.EncryptPathDirIV(plainPath, fs.args.Cipherdir, fs.args.EMENames)
}

// decryptPath - decrypt relative ciphertext path
func (fs *FS) decryptPath(cipherPath string) (string, error) {
	if fs.args.PlaintextNames {
		return cipherPath, nil
	}
	if !fs.args.DirIV {
		return fs.CryptFS.DecryptPathNoIV(cipherPath)
	}
	fs.dirIVLock.RLock()
	defer fs.dirIVLock.RUnlock()
	return fs.CryptFS.DecryptPathDirIV(cipherPath, fs.args.Cipherdir, fs.args.EMENames)
}
