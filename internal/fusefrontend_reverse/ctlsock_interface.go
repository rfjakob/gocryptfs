package fusefrontend_reverse

import (
	"errors"

	"github.com/rfjakob/gocryptfs/internal/ctlsock"
)

var _ ctlsock.Interface = &reverseFS{} // Verify that interface is implemented.

// EncryptPath implements ctlsock.Backend
func (rfs *reverseFS) EncryptPath(plainPath string) (string, error) {
	return "", errors.New("Not implemented")
}

// DecryptPath implements ctlsock.Backend
func (rfs *reverseFS) DecryptPath(plainPath string) (string, error) {
	return rfs.decryptPath(plainPath)
}
