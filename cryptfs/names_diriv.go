package cryptfs

import (
	"path/filepath"
	"io/ioutil"
	"fmt"
	"strings"
)

// readDirIV - read the "gocryptfs.diriv" file from "dir" (absolute path)
func (be *CryptFS) readDirIV(dir string) (iv []byte, err error) {
		ivfile := filepath.Join(dir, DIRIV_FILENAME)
		iv, err = ioutil.ReadFile(ivfile)
		if err != nil {
			Warn.Printf("readDirIV: %v\n", err)
			return nil, err
		}
		if len(iv) != DIRIV_LEN {
			return nil, fmt.Errorf("readDirIV: Invalid length %d\n", len(iv))
		}
		return iv, nil
}

// EncryptPathDirIV - encrypt path using CBC with DirIV
func (be *CryptFS) EncryptPathDirIV(plainPath string, rootDir string) (string, error) {
	if be.plaintextNames {
		return plainPath, nil
	}
	// Empty string means root directory
	if plainPath == "" {
		return plainPath, nil
	}
	var wd = rootDir
	var encryptedNames []string
	plainNames := strings.Split(plainPath, "/")
	for _, plainName := range plainNames {
		iv, err := be.readDirIV(wd)
		if err != nil {
			return "", err
		}
		encryptedName := be.encryptName(plainName, iv)
		encryptedNames = append(encryptedNames, encryptedName)
		wd = filepath.Join(wd, encryptedName)
	}
	return filepath.Join(encryptedNames...), nil
}

// DecryptPathDirIV - encrypt path using CBC with DirIV
func (be *CryptFS) DecryptPathDirIV(encryptedPath string, rootDir string) (string, error) {
	if be.plaintextNames {
		return encryptedPath, nil
	}
	var wd = rootDir
	var plainNames []string
	encryptedNames := strings.Split(encryptedPath, "/")
	for _, encryptedName := range encryptedNames {
		iv, err := be.readDirIV(wd)
		if err != nil {
			return "", err
		}
		plainName, err := be.decryptName(encryptedName, iv)
		if err != nil {
			return "", err
		}
		plainNames = append(plainNames, plainName)
		wd = filepath.Join(wd, encryptedName)
	}
	return filepath.Join(plainNames...), nil
}
