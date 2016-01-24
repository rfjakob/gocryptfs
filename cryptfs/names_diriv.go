package cryptfs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// A simple one-entry DirIV cache
type DirIVCache struct {
	// Invalidated?
	cleared bool
	// The DirIV
	iv []byte
	// Directory the DirIV belongs to
	dir string
	// Ecrypted version of "dir"
	translatedDir string
	// Synchronisation
	lock sync.RWMutex
}

// lookup - fetch entry for "dir" from the cache
func (c *DirIVCache) lookup(dir string) (bool, []byte, string) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if !c.cleared && c.dir == dir {
		return true, c.iv, c.translatedDir
	}
	return false, nil, ""
}

// store - write entry for "dir" into the caches
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
func (be *CryptFS) ReadDirIV(dir string) (iv []byte, readErr error) {
	ivfile := filepath.Join(dir, DIRIV_FILENAME)
	Debug.Printf("ReadDirIV: reading %s\n", ivfile)
	iv, readErr = ioutil.ReadFile(ivfile)
	if readErr != nil {
		// The directory may have been concurrently deleted or moved. Failure to
		// read the diriv is not an error in that case.
		_, statErr := os.Stat(dir)
		if os.IsNotExist(statErr) {
			Debug.Printf("ReadDirIV: Dir %s was deleted under our feet", dir)
		} else {
			// This should not happen
			Warn.Printf("ReadDirIV: Dir exists but diriv does not: %v\n", readErr)
		}
		return nil, readErr
	}
	if len(iv) != DIRIV_LEN {
		return nil, fmt.Errorf("ReadDirIV: Invalid length %d\n", len(iv))
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

// EncryptPathDirIV - encrypt path using EME with DirIV
func (be *CryptFS) EncryptPathDirIV(plainPath string, rootDir string, eme bool) (cipherPath string, err error) {
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
		cBaseName := be.encryptName(baseName, iv, eme)
		cipherPath = cParentDir + "/" + cBaseName
		return cipherPath, nil
	}
	// Walk the directory tree
	var wd = rootDir
	var encryptedNames []string
	plainNames := strings.Split(plainPath, "/")
	for _, plainName := range plainNames {
		iv, err = be.ReadDirIV(wd)
		if err != nil {
			return "", err
		}
		encryptedName := be.encryptName(plainName, iv, eme)
		encryptedNames = append(encryptedNames, encryptedName)
		wd = filepath.Join(wd, encryptedName)
	}
	// Cache the final DirIV
	cipherPath = strings.Join(encryptedNames, "/")
	cParentDir = filepath.Dir(cipherPath)
	be.DirIVCacheEnc.store(parentDir, iv, cParentDir)
	return cipherPath, nil
}

// DecryptPathDirIV - decrypt path using EME with DirIV
func (be *CryptFS) DecryptPathDirIV(encryptedPath string, rootDir string, eme bool) (string, error) {
	var wd = rootDir
	var plainNames []string
	encryptedNames := strings.Split(encryptedPath, "/")
	Debug.Printf("DecryptPathDirIV: decrypting %v\n", encryptedNames)
	for _, encryptedName := range encryptedNames {
		iv, err := be.ReadDirIV(wd)
		if err != nil {
			return "", err
		}
		plainName, err := be.decryptName(encryptedName, iv, eme)
		if err != nil {
			return "", err
		}
		plainNames = append(plainNames, plainName)
		wd = filepath.Join(wd, encryptedName)
	}
	return filepath.Join(plainNames...), nil
}
