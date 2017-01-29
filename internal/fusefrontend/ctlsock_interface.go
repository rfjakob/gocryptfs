package fusefrontend

import (
	"errors"

	"github.com/rfjakob/gocryptfs/internal/ctlsock"
)

var _ ctlsock.Interface = &FS{} // Verify that interface is implemented.

// EncryptPath implements ctlsock.Backend
func (fs *FS) EncryptPath(plainPath string) (string, error) {
	return fs.encryptPath(plainPath)
}

// DecryptPath implements ctlsock.Backend
func (fs *FS) DecryptPath(cipherPath string) (string, error) {
	return "", errors.New("Forward mode does not have path decryption implemented")
}
