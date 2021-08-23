package nametransform

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
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
//
// This function does not do any I/O.
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
//
// This function does not do any I/O.
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
//
// This function does not do any I/O.
func IsLongContent(cName string) bool {
	return NameType(cName) == LongNameContent
}

// RemoveLongNameSuffix removes the ".name" suffix from cName, returning the corresponding
// content file name.
// No check is made if cName actually is a LongNameFilename.
func RemoveLongNameSuffix(cName string) string {
	return cName[:len(cName)-len(LongNameSuffix)]
}

// ReadLongName - read cName + ".name" from the directory opened as dirfd.
//
// Symlink-safe through Openat().
func ReadLongNameAt(dirfd int, cName string) (string, error) {
	cName += LongNameSuffix
	var f *os.File
	{
		fd, err := syscallcompat.Openat(dirfd, cName, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return "", err
		}
		f = os.NewFile(uintptr(fd), "")
		// fd runs out of scope here
	}
	defer f.Close()
	// 256 (=255 padded to 16) bytes base64-encoded take 344 bytes: "AAAAAAA...AAA=="
	lim := 344
	// Allocate a bigger buffer so we see whether the file is too big
	buf := make([]byte, lim+1)
	n, err := f.ReadAt(buf, 0)
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

// DeleteLongName deletes "hashName.name" in the directory opened at "dirfd".
//
// This function is symlink-safe through the use of Unlinkat().
func DeleteLongNameAt(dirfd int, hashName string) error {
	err := syscallcompat.Unlinkat(dirfd, hashName+LongNameSuffix, 0)
	if err != nil {
		tlog.Warn.Printf("DeleteLongNameAt: %v", err)
	}
	return err
}

// WriteLongName encrypts plainName and writes it into "hashName.name".
// For the convenience of the caller, plainName may also be a path and will be
// Base()named internally.
//
// This function is symlink-safe through the use of Openat().
func (n *NameTransform) WriteLongNameAt(dirfd int, hashName string, plainName string) (err error) {
	plainName = filepath.Base(plainName)

	// Encrypt the basename
	dirIV, err := n.ReadDirIVAt(dirfd)
	if err != nil {
		return err
	}
	cName, err := n.EncryptName(plainName, dirIV)
	if err != nil {
		return err
	}

	// Write the encrypted name into hashName.name
	fdRaw, err := syscallcompat.Openat(dirfd, hashName+LongNameSuffix,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, namePerms)
	if err != nil {
		// Don't warn if the file already exists - this is allowed for renames
		// and should be handled by the caller.
		if err != syscall.EEXIST {
			tlog.Warn.Printf("WriteLongName: Openat: %v", err)
		}
		return err
	}
	fd := os.NewFile(uintptr(fdRaw), hashName+LongNameSuffix)
	_, err = fd.Write([]byte(cName))
	if err != nil {
		fd.Close()
		tlog.Warn.Printf("WriteLongName: Write: %v", err)
		// Delete incomplete longname file
		syscallcompat.Unlinkat(dirfd, hashName+LongNameSuffix, 0)
		return err
	}
	err = fd.Close()
	if err != nil {
		tlog.Warn.Printf("WriteLongName: Close: %v", err)
		// Delete incomplete longname file
		syscallcompat.Unlinkat(dirfd, hashName+LongNameSuffix, 0)
		return err
	}
	return nil
}
