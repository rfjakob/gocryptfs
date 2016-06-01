package nametransform

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/toggledlog"
)

const (
	// identical to AES block size
	dirIVLen = 16
	// dirIV is stored in this file. Exported because we have to ignore this
	// name in directory listing.
	DirIVFilename = "gocryptfs.diriv"
)

// ReadDirIV - read the "gocryptfs.diriv" file from "dir" (absolute ciphertext path)
// This function is exported because it allows for an efficient readdir implementation.
func ReadDirIV(dir string) (iv []byte, err error) {
	dirfd, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer dirfd.Close()

	return ReadDirIVAt(dirfd)
}

// ReadDirIVAt reads "gocryptfs.diriv" from the directory that is opened as "dirfd".
// Using the dirfd makes it immune to concurrent renames of the directory.
func ReadDirIVAt(dirfd *os.File) (iv []byte, err error) {
	fdRaw, err := syscall.Openat(int(dirfd.Fd()), DirIVFilename, syscall.O_RDONLY, 0)
	if err != nil {
		toggledlog.Warn.Printf("ReadDirIVAt: opening %q in dir %q failed: %v",
			DirIVFilename, dirfd.Name(), err)
		return nil, err
	}
	fd := os.NewFile(uintptr(fdRaw), DirIVFilename)
	defer fd.Close()

	iv = make([]byte, dirIVLen+1)
	n, err := fd.Read(iv)
	if err != nil {
		toggledlog.Warn.Printf("ReadDirIVAt: Read failed: %v", err)
		return nil, err
	}
	iv = iv[0:n]
	if len(iv) != dirIVLen {
		toggledlog.Warn.Printf("ReadDirIVAt: wanted %d bytes, got %d", dirIVLen, len(iv))
		return nil, errors.New("invalid iv length")
	}
	return iv, nil
}

// WriteDirIV - create diriv file inside "dir" (absolute ciphertext path)
// This function is exported because it is used from pathfs_frontend, main,
// and also the automated tests.
func WriteDirIV(dir string) error {
	iv := cryptocore.RandBytes(dirIVLen)
	file := filepath.Join(dir, DirIVFilename)
	err := ioutil.WriteFile(file, iv, 0400)
	if err != nil {
		toggledlog.Warn.Printf("WriteDirIV: %v", err)
	}
	return err
}

// EncryptPathDirIV - encrypt relative plaintext path using EME with DirIV.
// Components that are longer than 255 bytes are hashed if be.longnames == true.
func (be *NameTransform) EncryptPathDirIV(plainPath string, rootDir string) (cipherPath string, err error) {
	// Empty string means root directory
	if plainPath == "" {
		return plainPath, nil
	}
	// Reject names longer than 255 bytes already here. This relieves everybody
	// who uses hashed long names from checking for that later.
	baseName := filepath.Base(plainPath)
	if len(baseName) > syscall.NAME_MAX {
		return "", syscall.ENAMETOOLONG
	}
	// Check if the DirIV is cached
	parentDir := filepath.Dir(plainPath)
	found, iv, cParentDir := be.DirIVCache.lookup(parentDir)
	if found {
		cBaseName := be.EncryptName(baseName, iv)
		if be.longNames && len(cBaseName) > syscall.NAME_MAX {
			cBaseName = HashLongName(cBaseName)
		}
		cipherPath = cParentDir + "/" + cBaseName
		return cipherPath, nil
	}
	// Not cached - walk the directory tree
	var wd = rootDir
	var encryptedNames []string
	plainNames := strings.Split(plainPath, "/")
	for _, plainName := range plainNames {
		iv, err = ReadDirIV(wd)
		if err != nil {
			return "", err
		}
		encryptedName := be.EncryptName(plainName, iv)
		if be.longNames && len(encryptedName) > syscall.NAME_MAX {
			encryptedName = HashLongName(encryptedName)
		}
		encryptedNames = append(encryptedNames, encryptedName)
		wd = filepath.Join(wd, encryptedName)
	}
	cipherPath = strings.Join(encryptedNames, "/")
	// Cache the final DirIV
	cParentDir = filepath.Dir(cipherPath)
	be.DirIVCache.store(parentDir, iv, cParentDir)
	return cipherPath, nil
}

// DecryptPathDirIV - decrypt path using EME with DirIV
//
// TODO This has only a single user, Readlink(), and only for compatability with
// gocryptfs v0.5. Drop?
func (be *NameTransform) DecryptPathDirIV(encryptedPath string, rootDir string) (string, error) {
	var wd = rootDir
	var plainNames []string
	encryptedNames := strings.Split(encryptedPath, "/")
	toggledlog.Debug.Printf("DecryptPathDirIV: decrypting %v\n", encryptedNames)
	for _, encryptedName := range encryptedNames {
		iv, err := ReadDirIV(wd)
		if err != nil {
			return "", err
		}
		plainName, err := be.DecryptName(encryptedName, iv)
		if err != nil {
			return "", err
		}
		plainNames = append(plainNames, plainName)
		wd = filepath.Join(wd, encryptedName)
	}
	return filepath.Join(plainNames...), nil
}
