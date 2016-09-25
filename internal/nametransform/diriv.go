package nametransform

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// identical to AES block size
	DirIVLen = 16
	// dirIV is stored in this file. Exported because we have to ignore this
	// name in directory listing.
	DirIVFilename = "gocryptfs.diriv"
)

// ReadDirIV - read the "gocryptfs.diriv" file from "dir" (absolute ciphertext path)
// This function is exported because it allows for an efficient readdir implementation.
func ReadDirIV(dir string) (iv []byte, err error) {
	fd, err := os.Open(filepath.Join(dir, DirIVFilename))
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	return fdReadDirIV(fd)
}

// ReadDirIVAt reads "gocryptfs.diriv" from the directory that is opened as "dirfd".
// Using the dirfd makes it immune to concurrent renames of the directory.
func ReadDirIVAt(dirfd *os.File) (iv []byte, err error) {
	fdRaw, err := syscallcompat.Openat(int(dirfd.Fd()), DirIVFilename, syscall.O_RDONLY, 0)
	if err != nil {
		tlog.Warn.Printf("ReadDirIVAt: opening %q in dir %q failed: %v",
			DirIVFilename, dirfd.Name(), err)
		return nil, err
	}
	fd := os.NewFile(uintptr(fdRaw), DirIVFilename)
	defer fd.Close()
	return fdReadDirIV(fd)
}

// fdReadDirIV reads and verifies the DirIV from an opened gocryptfs.diriv file.
func fdReadDirIV(fd *os.File) (iv []byte, err error) {
	// We want to detect if the file is bigger than DirIVLen, so
	// make the buffer 1 byte bigger than neccessary.
	iv = make([]byte, DirIVLen+1)
	n, err := fd.Read(iv)
	if err != nil {
		tlog.Warn.Printf("ReadDirIVAt: Read failed: %v", err)
		return nil, err
	}
	iv = iv[0:n]
	if len(iv) != DirIVLen {
		tlog.Warn.Printf("ReadDirIVAt: wanted %d bytes, got %d", DirIVLen, len(iv))
		return nil, errors.New("invalid iv length")
	}
	return iv, nil
}

// WriteDirIV - create diriv file inside "dir" (absolute ciphertext path)
// This function is exported because it is used from pathfs_frontend, main,
// and also the automated tests.
func WriteDirIV(dir string) error {
	iv := cryptocore.RandBytes(DirIVLen)
	file := filepath.Join(dir, DirIVFilename)
	err := ioutil.WriteFile(file, iv, 0400)
	if err != nil {
		tlog.Warn.Printf("WriteDirIV: %v", err)
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
