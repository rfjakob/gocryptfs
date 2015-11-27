package pathfs_frontend

// This file handles filename encryption

func (fs *FS) encryptPath(plainPath string) (string, error) {
	fs.dirIVLock.RLock()
	defer fs.dirIVLock.RUnlock()
	return fs.CryptFS.EncryptPathDirIV(plainPath, fs.backingDir)
}

func (fs *FS) decryptPath(cipherPath string) (string, error) {
	fs.dirIVLock.RLock()
	defer fs.dirIVLock.RUnlock()
	return fs.CryptFS.DecryptPathDirIV(cipherPath, fs.backingDir)
}
