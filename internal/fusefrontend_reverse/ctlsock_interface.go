package fusefrontend_reverse

import (
	"errors"

	"github.com/rfjakob/gocryptfs/internal/ctlsock"
)

var _ ctlsock.Interface = &ReverseFS{} // Verify that interface is implemented.

// EncryptPath implements ctlsock.Backend
func (rfs *ReverseFS) EncryptPath(plainPath string) (string, error) {
	return "", errors.New("Not implemented")
}

// DecryptPath implements ctlsock.Backend
func (rfs *ReverseFS) DecryptPath(plainPath string) (string, error) {
	return rfs.decryptPath(plainPath)
}
