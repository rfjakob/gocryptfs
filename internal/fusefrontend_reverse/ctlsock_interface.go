package fusefrontend_reverse

import (
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/ctlsock"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

var _ ctlsock.Interface = &ReverseFS{} // Verify that interface is implemented.

// EncryptPath implements ctlsock.Backend.
// This is actually not used inside reverse mode, but we implement it because
// third-party tools want to encrypt paths through the control socket.
func (rfs *ReverseFS) EncryptPath(plainPath string) (string, error) {
	if rfs.args.PlaintextNames || plainPath == "" {
		return plainPath, nil
	}
	cipherPath := ""
	parts := strings.Split(plainPath, "/")
	for _, part := range parts {
		dirIV := derivePathIV(cipherPath, ivPurposeDirIV)
		encryptedPart := rfs.nameTransform.EncryptName(part, dirIV)
		if rfs.args.LongNames && len(encryptedPart) > syscall.NAME_MAX {
			encryptedPart = nametransform.HashLongName(encryptedPart)
		}
		cipherPath = filepath.Join(cipherPath, encryptedPart)
	}
	return cipherPath, nil
}

// DecryptPath implements ctlsock.Backend
func (rfs *ReverseFS) DecryptPath(cipherPath string) (string, error) {
	p, err := rfs.decryptPath(cipherPath)
	//fmt.Printf("rfs DecryptPath: %q -> %q %v\n", cipherPath, p, err)
	return p, err
}
