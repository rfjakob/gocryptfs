package fusefrontend

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/ctlsocksrv"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

var _ ctlsocksrv.Interface = &RootNode{} // Verify that interface is implemented.

// EncryptPath implements ctlsock.Backend
//
// Symlink-safe through openBackingDir().
func (rn *RootNode) EncryptPath(plainPath string) (string, error) {
	if plainPath == "" {
		// Empty string gets encrypted as empty string
		return plainPath, nil
	}
	if rn.args.PlaintextNames {
		return plainPath, nil
	}
	// Encrypt path level by level using openBackingDir. Pretty inefficient,
	// but does not matter here.
	parts := strings.Split(plainPath, "/")
	wd := ""
	cPath := ""
	for _, part := range parts {
		wd = filepath.Join(wd, part)
		dirfd, cName, err := rn.openBackingDir(wd)
		if err != nil {
			return "", err
		}
		syscall.Close(dirfd)
		cPath = filepath.Join(cPath, cName)
	}
	tlog.Debug.Printf("encryptPath '%s' -> '%s'", plainPath, cPath)
	return cPath, nil
}

// DecryptPath implements ctlsock.Backend
//
// DecryptPath is symlink-safe because openBackingDir() and decryptPathAt()
// are symlink-safe.
func (rn *RootNode) DecryptPath(cipherPath string) (plainPath string, err error) {
	dirfd, _, err := rn.openBackingDir("")
	if err != nil {
		return "", err
	}
	defer syscall.Close(dirfd)
	return rn.decryptPathAt(dirfd, cipherPath)
}

// decryptPathAt decrypts a ciphertext path relative to dirfd.
//
// Symlink-safe through ReadDirIVAt() and ReadLongNameAt().
func (rn *RootNode) decryptPathAt(dirfd int, cipherPath string) (plainPath string, err error) {
	if rn.args.PlaintextNames || cipherPath == "" {
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
		name, err := rn.nameTransform.DecryptName(longPart, dirIV)
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
		wd, err = syscallcompat.Openat(wd, part, syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err != nil {
			return "", err
		}
		// Yes this is somewhat wasteful in terms of used file descriptors:
		// we keep them all open until the function returns. But it is simple
		// and reliable.
		defer syscall.Close(wd)
	}

	return plainPath, nil
}
