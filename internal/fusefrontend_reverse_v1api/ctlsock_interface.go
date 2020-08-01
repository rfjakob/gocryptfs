package fusefrontend_reverse

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/internal/ctlsocksrv"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
)

var _ ctlsocksrv.Interface = &ReverseFS{} // Verify that interface is implemented.

// EncryptPath implements ctlsock.Backend.
// This is used for the control socket and for the "-exclude" logic.
func (rfs *ReverseFS) EncryptPath(plainPath string) (string, error) {
	if rfs.args.PlaintextNames || plainPath == "" {
		return plainPath, nil
	}
	cipherPath := ""
	parts := strings.Split(plainPath, "/")
	for _, part := range parts {
		dirIV := pathiv.Derive(cipherPath, pathiv.PurposeDirIV)
		encryptedPart := rfs.nameTransform.EncryptName(part, dirIV)
		if rfs.args.LongNames && len(encryptedPart) > unix.NAME_MAX {
			encryptedPart = rfs.nameTransform.HashLongName(encryptedPart)
		}
		cipherPath = filepath.Join(cipherPath, encryptedPart)
	}
	return cipherPath, nil
}

// DecryptPath implements ctlsock.Backend
func (rfs *ReverseFS) DecryptPath(cipherPath string) (string, error) {
	p, err := rfs.decryptPath(cipherPath)
	return p, err
}
