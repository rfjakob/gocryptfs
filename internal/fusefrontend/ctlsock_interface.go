package fusefrontend

import (
	"fmt"
	"path"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/ctlsock"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
)

var _ ctlsock.Interface = &FS{} // Verify that interface is implemented.

// EncryptPath implements ctlsock.Backend
func (fs *FS) EncryptPath(plainPath string) (string, error) {
	return fs.encryptPath(plainPath)
}

// DecryptPath implements ctlsock.Backend
func (fs *FS) DecryptPath(cipherPath string) (plainPath string, err error) {
	dirfd, err := syscall.Open(fs.args.Cipherdir, syscall.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer syscall.Close(dirfd)
	return fs.decryptPathAt(dirfd, cipherPath)
}

// decryptPathAt decrypts a ciphertext path relative to dirfd.
func (fs *FS) decryptPathAt(dirfd int, cipherPath string) (plainPath string, err error) {
	if fs.args.PlaintextNames || cipherPath == "" {
		return cipherPath, nil
	}
	parts := strings.Split(cipherPath, "/")
	wd := dirfd
	for i, part := range parts {
		dirIV, err := nametransform.ReadDirIVAt(wd)
		if err != nil {
			fmt.Printf("ReadDirIV: %v\n", err)
			return "", err
		}
		longPart := part
		if nametransform.IsLongContent(part) {
			longPart, err = nametransform.ReadLongNameAt(wd, part)
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
		// Last path component? We are done.
		if i == len(parts)-1 {
			break
		}
		// Descend into next directory
		oldWd := wd
		wd, err = syscallcompat.Openat(wd, part, syscall.O_NOFOLLOW, 0)
		if err != nil {
			return "", err
		}
		// Unless we are in the first iteration, where dirfd is our wd, close
		// the old working directory.
		if i > 0 {
			syscall.Close(oldWd)
		}
	}
	return plainPath, nil
}
