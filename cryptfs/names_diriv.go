package cryptfs

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"
)

// A simple one-entry DirIV cache
type DirIVCache struct {
	// Invalidated?
	cleared       bool
	// The DirIV
	iv            []byte
	// Directory the DirIV belongs to
	dir           string
	// Ecrypted version of "dir"
	translatedDir string
	// Synchronisation
	lock          sync.RWMutex
}

func (c *DirIVCache) lookup(dir string) (bool, []byte, string) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if !c.cleared && c.dir == dir {
		return true, c.iv, c.translatedDir
	}
	return false, nil, ""
}

func (c *DirIVCache) store(dir string, iv []byte, translatedDir string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.cleared = false
	c.iv = iv
	c.dir = dir
	c.translatedDir = translatedDir
}

func (c *DirIVCache) Clear() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.cleared = true
}

// readDirIV - read the "gocryptfs.diriv" file from "dir" (absolute ciphertext path)
func (be *CryptFS) ReadDirIV(dir string) (iv []byte, err error) {
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

// WriteDirIV - create diriv file inside "dir" (absolute ciphertext path)
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
	// Check if the DirIV is cached
	parentDir := filepath.Dir(plainPath)
	found, iv, cParentDir := be.DirIVCacheEnc.lookup(parentDir)
	if found {
		//fmt.Print("h")
		baseName := filepath.Base(plainPath)
		cBaseName := be.encryptName(baseName, iv)
		cPath := cParentDir + "/" + cBaseName
		return cPath, nil
	}
	// Walk the directory tree
	var wd = rootDir
	var encryptedNames []string
	var err error
	plainNames := strings.Split(plainPath, "/")
	for _, plainName := range plainNames {
		iv, err = be.ReadDirIV(wd)
		if err != nil {
			return "", err
		}
		encryptedName := be.encryptName(plainName, iv)
		encryptedNames = append(encryptedNames, encryptedName)
		wd = filepath.Join(wd, encryptedName)
	}
	// Cache the final DirIV
	cPath := strings.Join(encryptedNames, "/")
	cParentDir = filepath.Dir(cPath)
	be.DirIVCacheEnc.store(parentDir, iv, cParentDir)
	return cPath, nil
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
		iv, err := be.ReadDirIV(wd)
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
