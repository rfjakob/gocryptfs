package nametransform

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// LongNameSuffix is the suffix used for files with long names.
	// Files with long names are stored in two files:
	// gocryptfs.longname.[sha256]       <--- File content, prefix = gocryptfs.longname.
	// gocryptfs.longname.[sha256].name  <--- File name, suffix = .name
	LongNameSuffix = ".name"
	longNamePrefix = "gocryptfs.longname."
)

// HashLongName - take the hash of a long string "name" and return
// "gocryptfs.longname.[sha256]"
func (n *NameTransform) HashLongName(name string) string {
	hashBin := sha256.Sum256([]byte(name))
	hashBase64 := n.B64.EncodeToString(hashBin[:])
	return longNamePrefix + hashBase64
}

// Values returned by IsLongName
const (
	// LongNameContent is the file that stores the file content.
	// Example: gocryptfs.longname.URrM8kgxTKYMgCk4hKk7RO9Lcfr30XQof4L_5bD9Iro=
	LongNameContent = iota
	// LongNameFilename is the file that stores the full encrypted filename.
	// Example: gocryptfs.longname.URrM8kgxTKYMgCk4hKk7RO9Lcfr30XQof4L_5bD9Iro=.name
	LongNameFilename = iota
	// LongNameNone is used when the file does not have a long name.
	// Example: i1bpTaVLZq7sRNA9mL_2Ig==
	LongNameNone = iota
)

// NameType - detect if cName is
// gocryptfs.longname.[sha256]  ........ LongNameContent (content of a long name file)
// gocryptfs.longname.[sha256].name .... LongNameFilename (full file name of a long name file)
// else ................................ LongNameNone (normal file)
func NameType(cName string) int {
	if !strings.HasPrefix(cName, longNamePrefix) {
		return LongNameNone
	}
	if strings.HasSuffix(cName, LongNameSuffix) {
		return LongNameFilename
	}
	return LongNameContent
}

// IsLongContent returns true if "cName" is the content store of a long name
// file (looks like "gocryptfs.longname.[sha256]").
func IsLongContent(cName string) bool {
	return NameType(cName) == LongNameContent
}

// ReadLongName - read "$path.name"
func ReadLongName(path string) (string, error) {
	path += LongNameSuffix
	fd, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fd.Close()
	// 256 (=255 padded to 16) bytes base64-encoded take 344 bytes: "AAAAAAA...AAA=="
	lim := 344
	// Allocate a bigger buffer so we see whether the file is too big
	buf := make([]byte, lim+1)
	n, err := fd.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return "", err
	}
	if n == 0 {
		return "", fmt.Errorf("ReadLongName: empty file")
	}
	if n > lim {
		return "", fmt.Errorf("ReadLongName: size=%d > limit=%d", n, lim)
	}
	return string(buf[0:n]), nil
}

// DeleteLongName deletes "hashName.name".
func DeleteLongName(dirfd *os.File, hashName string) error {
	err := syscallcompat.Unlinkat(int(dirfd.Fd()), hashName+LongNameSuffix)
	if err != nil {
		tlog.Warn.Printf("DeleteLongName: %v", err)
	}
	return err
}

// WriteLongName encrypts plainName and writes it into "hashName.name".
// For the convenience of the caller, plainName may also be a path and will be
// converted internally.
func (n *NameTransform) WriteLongName(dirfd *os.File, hashName string, plainName string) (err error) {
	plainName = filepath.Base(plainName)

	// Encrypt the basename
	dirIV, err := ReadDirIVAt(dirfd)
	if err != nil {
		return err
	}
	cName := n.EncryptName(plainName, dirIV)

	// Write the encrypted name into hashName.name
	fdRaw, err := syscallcompat.Openat(int(dirfd.Fd()), hashName+LongNameSuffix,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600)
	if err != nil {
		// Don't warn if the file already exists - this is allowed for renames
		// and should be handled by the caller.
		if err != syscall.EEXIST {
			tlog.Warn.Printf("WriteLongName: Openat: %v", err)
		}
		return err
	}
	fd := os.NewFile(uintptr(fdRaw), hashName+LongNameSuffix)
	defer fd.Close()
	_, err = fd.Write([]byte(cName))
	if err != nil {
		tlog.Warn.Printf("WriteLongName: Write: %v", err)
	}
	return err
}
