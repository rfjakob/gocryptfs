package nametransform

import (
	"syscall"
	"path/filepath"
	"io/ioutil"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/rfjakob/gocryptfs/internal/toggledlog"
)

// Files with long names are stored in two files:
// gocryptfs.longname.[sha256]       <--- File content
// gocryptfs.longname.[sha256].name  <--- File name
const longNamePrefix = "gocryptfs.longname."
const longNameSuffix = ".name"

// HashLongName - take the hash of a long string "name" and return
// "gocryptfs.longname.[sha256]"
func HashLongName(name string) string {
	hashBin := sha256.Sum256([]byte(name))
	hashBase64 := base64.URLEncoding.EncodeToString(hashBin[:])
	return longNamePrefix + hashBase64
}

// IsLongName - detect if cName is
// gocryptfs.longname.* ........ 1
// gocryptfs.longname.*.name ... 2
// else ........................ 0
func IsLongName(cName string) int {
	if !strings.HasPrefix(cName, longNamePrefix) {
		return 0
	}
	if strings.HasSuffix(cName, longNameSuffix) {
		return 2
	}
	return 1
}

// ReadLongName - read "path".name
func ReadLongName(path string) (string, error) {
	content, err := ioutil.ReadFile(path+longNameSuffix)
	if err != nil {
		toggledlog.Warn.Printf("ReadLongName: %v", err)
	}
	return string(content), err
}

// WriteLongName -
func (n *NameTransform) WriteLongName(cDir string, hashedName string, plainName string) (err error) {
	if len(plainName) > syscall.NAME_MAX {
		return syscall.ENAMETOOLONG
	}

	dirIV, err := ReadDirIV(cDir)
	if err != nil {
		toggledlog.Warn.Printf("WriteLongName: %v", err)
		return err
	}
	cName := n.EncryptName(plainName, dirIV)
	err = ioutil.WriteFile(filepath.Join(cDir, hashedName + longNameSuffix), []byte(cName), 0600)
	if err != nil {
		toggledlog.Warn.Printf("WriteLongName: %v", err)
	}
	return err
}
