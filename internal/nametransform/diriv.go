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

// EncryptPathDirIV - encrypt relative plaintext path "plainPath" using EME with
// DirIV. "rootDir" is the backing storage root directory.
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
	// Check if the DirIV is cached. This catches the case of the user iterating
	// over files in a directory pretty well.
	parentDir := filepath.Dir(plainPath)
	iv, cParentDir := be.DirIVCache.lookup(parentDir)
	if iv != nil {
		cBaseName := be.EncryptName(baseName, iv)
		if be.longNames && len(cBaseName) > syscall.NAME_MAX {
			cBaseName = be.HashLongName(cBaseName)
		}
		cipherPath = filepath.Join(cParentDir, cBaseName)
		return cipherPath, nil
	}
	// We have to walk the directory tree, in the worst case starting at the root
	// directory.
	wd := rootDir
	plainNames := strings.Split(plainPath, "/")
	// So the DirIV we need is not cached. But maybe one level higher is
	// cached. Then we can skip a few items in the directory walk.
	// The catches the case of walking directories recursively.
	parentDir2 := filepath.Dir(parentDir)
	iv, cParentDir = be.DirIVCache.lookup(parentDir2)
	if iv != nil {
		parentDirBase := filepath.Base(parentDir)
		cBaseName := be.EncryptName(parentDirBase, iv)
		if be.longNames && len(cBaseName) > syscall.NAME_MAX {
			cBaseName = be.HashLongName(cBaseName)
		}
		wd = filepath.Join(wd, cParentDir, cBaseName)
		cipherPath = filepath.Join(cParentDir, cBaseName)
		skip := len(strings.Split(cipherPath, "/"))
		plainNames = plainNames[skip:]
	}
	// Walk the directory tree starting at "wd"
	for _, plainName := range plainNames {
		iv, err = ReadDirIV(wd)
		if err != nil {
			return "", err
		}
		encryptedName := be.EncryptName(plainName, iv)
		if be.longNames && len(encryptedName) > syscall.NAME_MAX {
			encryptedName = be.HashLongName(encryptedName)
		}
		cipherPath = filepath.Join(cipherPath, encryptedName)
		wd = filepath.Join(wd, encryptedName)
	}
	// Cache the final DirIV
	cParentDir = filepath.Dir(cipherPath)
	be.DirIVCache.store(parentDir, iv, cParentDir)
	return cipherPath, nil
}
