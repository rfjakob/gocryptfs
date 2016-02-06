package nametransform

import (
	"syscall"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

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
// This function is exported because it allows for an efficient readdir implementation
func ReadDirIV(dir string) (iv []byte, readErr error) {
	ivfile := filepath.Join(dir, DirIVFilename)
	toggledlog.Debug.Printf("ReadDirIV: reading %s\n", ivfile)
	iv, readErr = ioutil.ReadFile(ivfile)
	if readErr != nil {
		// The directory may have been concurrently deleted or moved. Failure to
		// read the diriv is not an error in that case.
		_, statErr := os.Stat(dir)
		if os.IsNotExist(statErr) {
			toggledlog.Debug.Printf("ReadDirIV: Dir %s was deleted under our feet", dir)
		} else {
			// This should not happen
			toggledlog.Warn.Printf("ReadDirIV: Dir exists but diriv does not: %v\n", readErr)
		}
		return nil, readErr
	}
	if len(iv) != dirIVLen {
		return nil, fmt.Errorf("ReadDirIV: Invalid length %d\n", len(iv))
	}
	return iv, nil
}

// WriteDirIV - create diriv file inside "dir" (absolute ciphertext path)
// This function is exported because it is used from pathfs_frontend, main,
// and also the automated tests.
func WriteDirIV(dir string) error {
	iv := cryptocore.RandBytes(dirIVLen)
	file := filepath.Join(dir, DirIVFilename)
	// 0444 permissions: the file is not secret but should not be written to
	return ioutil.WriteFile(file, iv, 0444)
}

// EncryptPathDirIV - encrypt path using EME with DirIV
func (be *NameTransform) EncryptPathDirIV(plainPath string, rootDir string) (cipherPath string, err error) {
	// Empty string means root directory
	if plainPath == "" {
		return plainPath, nil
	}
	// Check if the DirIV is cached
	parentDir := filepath.Dir(plainPath)
	found, iv, cParentDir := be.DirIVCache.lookup(parentDir)
	if found {
		baseName := filepath.Base(plainPath)
		cBaseName := be.EncryptName(baseName, iv)
		if be.longNames && len(cBaseName) > syscall.NAME_MAX {
			cBaseName = HashLongName(cBaseName)
		}
		cipherPath = cParentDir + "/" + cBaseName
		return cipherPath, nil
	}
	// Walk the directory tree
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
