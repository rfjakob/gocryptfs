package fusefrontend_reverse

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/internal/ctlsocksrv"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
)

// Verify that the interface is implemented.
var _ ctlsocksrv.Interface = &RootNode{}

// EncryptPath implements ctlsock.Backend.
// This is used for the control socket and for the "-exclude" logic.
func (rn *RootNode) EncryptPath(plainPath string) (string, error) {
	if rn.args.PlaintextNames || plainPath == "" {
		return plainPath, nil
	}
	cipherPath := ""
	parts := strings.Split(plainPath, "/")
	for _, part := range parts {
		dirIV := pathiv.Derive(cipherPath, pathiv.PurposeDirIV)
		encryptedPart := rn.nameTransform.EncryptName(part, dirIV)
		if rn.args.LongNames && len(encryptedPart) > unix.NAME_MAX {
			encryptedPart = rn.nameTransform.HashLongName(encryptedPart)
		}
		cipherPath = filepath.Join(cipherPath, encryptedPart)
	}
	return cipherPath, nil
}

// DecryptPath implements ctlsock.Backend
func (rn *RootNode) DecryptPath(cipherPath string) (string, error) {
	p, err := rn.decryptPath(cipherPath)
	return p, err
}
