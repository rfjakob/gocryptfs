package pathfs_frontend

// This file forwards file encryption operations to cryptfs

import (
	"github.com/rfjakob/gocryptfs/cryptfs"
)

func (fs *FS) encryptPath(plainPath string) (string, error) {
	if !fs.args.DirIV {
		return fs.CryptFS.TranslatePathZeroIV(plainPath, cryptfs.OpEncrypt)
	}
	fs.dirIVLock.RLock()
	defer fs.dirIVLock.RUnlock()
	return fs.CryptFS.EncryptPathDirIV(plainPath, fs.args.Cipherdir)
}

func (fs *FS) decryptPath(cipherPath string) (string, error) {
	if !fs.args.DirIV {
		return fs.CryptFS.TranslatePathZeroIV(cipherPath, cryptfs.OpDecrypt)
	}
	fs.dirIVLock.RLock()
	defer fs.dirIVLock.RUnlock()
	return fs.CryptFS.DecryptPathDirIV(cipherPath, fs.args.Cipherdir)
}
