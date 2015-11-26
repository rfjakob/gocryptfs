package pathfs_frontend

// This file handles filename encryption

func (fs *FS) encryptPath(plainPath string) (string, error) {
	return fs.CryptFS.EncryptPathDirIV(plainPath, fs.backingDir)
}

func (fs *FS) decryptPath(cipherPath string) (string, error) {
	return fs.CryptFS.DecryptPathDirIV(cipherPath, fs.backingDir)
}
