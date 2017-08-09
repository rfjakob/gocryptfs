package nametransform

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// DirIVLen is identical to AES block size
	DirIVLen = 16
	// DirIVFilename is the filename used to store directory IV.
	// Exported because we have to ignore this name in directory listing.
	DirIVFilename = "gocryptfs.diriv"
)

// ReadDirIV - read the "gocryptfs.diriv" file from "dir" (absolute ciphertext path)
// This function is exported because it allows for an efficient readdir implementation.
func ReadDirIV(dir string) (iv []byte, err error) {
	fd, err := os.Open(filepath.Join(dir, DirIVFilename))
	if err != nil {
		// Note: getting errors here is normal because of concurrent deletes.
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

// allZeroDirIV is preallocated to quickly check if the data read from disk is all zero
var allZeroDirIV = make([]byte, DirIVLen)

// fdReadDirIV reads and verifies the DirIV from an opened gocryptfs.diriv file.
func fdReadDirIV(fd *os.File) (iv []byte, err error) {
	// We want to detect if the file is bigger than DirIVLen, so
	// make the buffer 1 byte bigger than necessary.
	iv = make([]byte, DirIVLen+1)
	n, err := fd.Read(iv)
	if err != nil && err != io.EOF {
		tlog.Warn.Printf("ReadDirIVAt: Read failed: %v", err)
		return nil, err
	}
	iv = iv[0:n]
	if len(iv) != DirIVLen {
		tlog.Warn.Printf("ReadDirIVAt: wanted %d bytes, got %d. Returning EINVAL.", DirIVLen, len(iv))
		return nil, syscall.EINVAL
	}
	if bytes.Equal(iv, allZeroDirIV) {
		tlog.Warn.Printf("ReadDirIVAt: diriv is all-zero. Returning EINVAL.")
		return nil, syscall.EINVAL
	}
	return iv, nil
}

// WriteDirIV - create diriv file inside "dir" (absolute ciphertext path)
// This function is exported because it is used from pathfs_frontend, main,
// and also the automated tests.
func WriteDirIV(dir string) error {
	iv := cryptocore.RandBytes(DirIVLen)
	file := filepath.Join(dir, DirIVFilename)
	// 0400 permissions: gocryptfs.diriv should never be modified after creation.
	// Don't use "ioutil.WriteFile", it causes trouble on NFS: https://github.com/rfjakob/gocryptfs/issues/105
	fd, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		tlog.Warn.Printf("WriteDirIV: OpenFile: %v", err)
		return err
	}
	_, err = fd.Write(iv)
	if err != nil {
		tlog.Warn.Printf("WriteDirIV: Write: %v", err)
		return err
	}
	err = fd.Close()
	if err != nil {
		tlog.Warn.Printf("WriteDirIV: Close: %v", err)
		return err
	}
	return nil
}

// encryptAndHashName encrypts "name" and hashes it to a longname if it is
// too long.
func (be *NameTransform) encryptAndHashName(name string, iv []byte) string {
	cName := be.EncryptName(name, iv)
	if be.longNames && len(cName) > syscall.NAME_MAX {
		return be.HashLongName(cName)
	}
	return cName
}

// EncryptPathDirIV - encrypt relative plaintext path "plainPath" using EME with
// DirIV. "rootDir" is the backing storage root directory.
// Components that are longer than 255 bytes are hashed if be.longnames == true.
func (be *NameTransform) EncryptPathDirIV(plainPath string, rootDir string) (string, error) {
	var err error
	// Empty string means root directory
	if plainPath == "" {
		return plainPath, nil
	}
	// Reject names longer than 255 bytes.
	baseName := filepath.Base(plainPath)
	if len(baseName) > syscall.NAME_MAX {
		return "", syscall.ENAMETOOLONG
	}
	// If we have the iv and the encrypted directory name in the cache, we
	// can skip the directory walk. This optimization yields a 10% improvement
	// in the tar extract benchmark.
	parentDir := Dir(plainPath)
	if iv, cParentDir := be.DirIVCache.Lookup(parentDir); iv != nil {
		cBaseName := be.encryptAndHashName(baseName, iv)
		return filepath.Join(cParentDir, cBaseName), nil
	}
	// We have to walk the directory tree, starting at the root directory.
	// ciphertext working directory (relative path)
	cipherWD := ""
	// plaintext working directory (relative path)
	plainWD := ""
	plainNames := strings.Split(plainPath, "/")
	for _, plainName := range plainNames {
		iv, _ := be.DirIVCache.Lookup(plainWD)
		if iv == nil {
			iv, err = ReadDirIV(filepath.Join(rootDir, cipherWD))
			if err != nil {
				return "", err
			}
			be.DirIVCache.Store(plainWD, iv, cipherWD)
		}
		cipherName := be.encryptAndHashName(plainName, iv)
		cipherWD = filepath.Join(cipherWD, cipherName)
		plainWD = filepath.Join(plainWD, plainName)
	}
	return cipherWD, nil
}

// Dir is like filepath.Dir but returns "" instead of ".".
func Dir(path string) string {
	d := filepath.Dir(path)
	if d == "." {
		return ""
	}
	return d
}
