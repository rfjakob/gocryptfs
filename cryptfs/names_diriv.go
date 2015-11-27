package cryptfs

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
)

// readDirIV - read the "gocryptfs.diriv" file from "dir" (absolute path)
func (be *CryptFS) readDirIV(dir string) (iv []byte, err error) {
	ivfile := filepath.Join(dir, DIRIV_FILENAME)
	Debug.Printf("readDirIV: reading %s\n", ivfile)
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

// WriteDirIV - create diriv file inside "dir" (absolute path)
// This function is exported because it is used from pathfs_frontend, main,
// and also the automated tests.
func WriteDirIV(dir string) error {
	iv := RandBytes(DIRIV_LEN)
	file := filepath.Join(dir, DIRIV_FILENAME)
	// 0444 permissions: the file is not secret but should not be written to
	return ioutil.WriteFile(file, iv, 0444)
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
	Debug.Printf("DecryptPathDirIV: decrypting %v\n", encryptedNames)
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
