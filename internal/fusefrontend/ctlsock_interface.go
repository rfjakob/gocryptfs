package fusefrontend

import (
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/ctlsocksrv"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var _ ctlsocksrv.Interface = &RootNode{} // Verify that interface is implemented.

// EncryptPath implements ctlsock.Backend
//
// Symlink-safe through openBackingDir().
func (rn *RootNode) EncryptPath(plainPath string) (cipherPath string, err error) {
	if rn.args.PlaintextNames || plainPath == "" {
		return plainPath, nil
	}

	dirfd, _, errno := rn.prepareAtSyscallMyself()
	if errno != 0 {
		return "", errno
	}
	defer syscall.Close(dirfd)

	// Encrypt path level by level
	parts := strings.Split(plainPath, "/")
	wd := dirfd
	for i, part := range parts {
		dirIV, err := rn.nameTransform.ReadDirIVAt(wd)
		if err != nil {
			return "", err
		}
		cPart, err := rn.nameTransform.EncryptAndHashName(part, dirIV)
		if err != nil {
			return "", err
		}
		cipherPath = filepath.Join(cipherPath, cPart)
		// Last path component? We are done.
		if i == len(parts)-1 {
			break
		}
		// Descend into next directory
		wd, err = syscallcompat.Openat(wd, cPart, syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err != nil {
			return "", err
		}
		// Yes this is somewhat wasteful in terms of used file descriptors:
		// we keep them all open until the function returns. But it is simple
		// and reliable.
		defer syscall.Close(wd)
	}
	tlog.Debug.Printf("EncryptPath %q -> %q", plainPath, cipherPath)
	return cipherPath, nil
}

// DecryptPath implements ctlsock.Backend
//
// DecryptPath is symlink-safe because openBackingDir() and decryptPathAt()
// are symlink-safe.
func (rn *RootNode) DecryptPath(cipherPath string) (plainPath string, err error) {
	if rn.args.PlaintextNames || cipherPath == "" {
		return cipherPath, nil
	}

	dirfd, _, errno := rn.prepareAtSyscallMyself()
	if errno != 0 {
		return "", errno
	}
	defer syscall.Close(dirfd)

	// Decrypt path level by level
	parts := strings.Split(cipherPath, "/")
	wd := dirfd
	for i, part := range parts {
		dirIV, err := rn.nameTransform.ReadDirIVAt(wd)
		if err != nil {
			return "", err
		}
		longPart := part
		if nametransform.IsLongContent(part) {
			longPart, err = nametransform.ReadLongNameAt(wd, part)
			if err != nil {
				return "", err
			}
		}
		name, err := rn.nameTransform.DecryptName(longPart, dirIV)
		if err != nil {
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
