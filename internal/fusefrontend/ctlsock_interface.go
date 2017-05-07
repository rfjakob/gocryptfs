package fusefrontend

import (
	"fmt"
	"path"
	"strings"

	"github.com/rfjakob/gocryptfs/internal/ctlsock"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

var _ ctlsock.Interface = &FS{} // Verify that interface is implemented.

// EncryptPath implements ctlsock.Backend
func (fs *FS) EncryptPath(plainPath string) (string, error) {
	return fs.encryptPath(plainPath)
}

// DecryptPath implements ctlsock.Backend
func (fs *FS) DecryptPath(cipherPath string) (string, error) {
	if fs.args.PlaintextNames || cipherPath == "" {
		return cipherPath, nil
	}
	plainPath := ""
	parts := strings.Split(cipherPath, "/")
	wd := fs.args.Cipherdir
	for _, part := range parts {
		dirIV, err := nametransform.ReadDirIV(wd)
		if err != nil {
			fmt.Printf("ReadDirIV: %v\n", err)
			return "", err
		}
		longPart := part
		if nametransform.IsLongContent(part) {
			longPart, err = nametransform.ReadLongName(wd + "/" + part)
			if err != nil {
				fmt.Printf("ReadLongName: %v\n", err)
				return "", err
			}
		}
		name, err := fs.nameTransform.DecryptName(longPart, dirIV)
		if err != nil {
			fmt.Printf("DecryptName: %v\n", err)
			return "", err
		}
		plainPath = path.Join(plainPath, name)
		wd = path.Join(wd, part)
	}
	return plainPath, nil
}
