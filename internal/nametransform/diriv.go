package nametransform

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
	"golang.org/x/sys/unix"
)

const (
	// DirIVLen is identical to AES block size
	DirIVLen = 16
	// DirIVFilename is the filename used to store directory IV.
	// Exported because we have to ignore this name in directory listing.
	DirIVFilename = "gocryptfs.diriv"
)

// ReadDirIVAt reads "gocryptfs.diriv" from the directory that is opened as "dirfd".
// Using the dirfd makes it immune to concurrent renames of the directory.
// Retries on EINTR.
func ReadDirIVAt(dirfd int) (iv []byte, err error) {
	fdRaw, err := syscallcompat.Openat(dirfd, DirIVFilename,
		syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
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
		return nil, fmt.Errorf("read failed: %v", err)
	}
	iv = iv[0:n]
	if len(iv) != DirIVLen {
		return nil, fmt.Errorf("wanted %d bytes, got %d", DirIVLen, len(iv))
	}
	if bytes.Equal(iv, allZeroDirIV) {
		return nil, fmt.Errorf("diriv is all-zero")
	}
	return iv, nil
}

// WriteDirIVAt - create a new gocryptfs.diriv file in the directory opened at
// "dirfd". On error we try to delete the incomplete file.
// This function is exported because it is used from fusefrontend, main,
// and also the automated tests.
func WriteDirIVAt(dirfd int) error {
	iv := cryptocore.RandBytes(DirIVLen)
	// 0400 permissions: gocryptfs.diriv should never be modified after creation.
	// Don't use "ioutil.WriteFile", it causes trouble on NFS:
	// https://github.com/rfjakob/gocryptfs/commit/7d38f80a78644c8ec4900cc990bfb894387112ed
	fd, err := syscallcompat.Openat(dirfd, DirIVFilename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, dirivPerms)
	if err != nil {
		tlog.Warn.Printf("WriteDirIV: Openat: %v", err)
		return err
	}
	// Wrap the fd in an os.File - we need the write retry logic.
	f := os.NewFile(uintptr(fd), DirIVFilename)
	_, err = f.Write(iv)
	if err != nil {
		f.Close()
		// It is normal to get ENOSPC here
		if !syscallcompat.IsENOSPC(err) {
			tlog.Warn.Printf("WriteDirIV: Write: %v", err)
		}
		// Delete incomplete gocryptfs.diriv file
		syscallcompat.Unlinkat(dirfd, DirIVFilename, 0)
		return err
	}
	err = f.Close()
	if err != nil {
		tlog.Warn.Printf("WriteDirIV: Close: %v", err)
		// Delete incomplete gocryptfs.diriv file
		syscallcompat.Unlinkat(dirfd, DirIVFilename, 0)
		return err
	}
	return nil
}

// encryptAndHashName encrypts "name" and hashes it to a longname if it is
// too long.
// Returns ENAMETOOLONG if "name" is longer than 255 bytes.
func (be *NameTransform) EncryptAndHashName(name string, iv []byte) (string, error) {
	// Prevent the user from creating files longer than 255 chars.
	if len(name) > NameMax {
		return "", syscall.ENAMETOOLONG
	}
	cName, err := be.EncryptName(name, iv)
	if err != nil {
		return "", err
	}
	if be.longNames && len(cName) > NameMax {
		return be.HashLongName(cName), nil
	}
	return cName, nil
}

// EncryptAndHashBadName tries to find the "name" substring, which (encrypted and hashed)
// leads to an unique existing file
// Returns ENOENT if cipher file does not exist or is not unique
func (be *NameTransform) EncryptAndHashBadName(name string, iv []byte, dirfd int) (cName string, err error) {
	var st unix.Stat_t
	var filesFound int
	lastFoundName, err := be.EncryptAndHashName(name, iv)
	if !strings.HasSuffix(name, BadNameFlag) || err != nil {
		//Default mode: same behaviour on error or no BadNameFlag on "name"
		return lastFoundName, err
	}
	//Default mode: Check if File extists without modifications
	err = syscallcompat.Fstatat(dirfd, lastFoundName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		//file found, return result
		return lastFoundName, nil
	}
	//BadName Mode: check if the name was tranformed without change (badname suffix and undecryptable cipher name)
	err = syscallcompat.Fstatat(dirfd, name[:len(name)-len(BadNameFlag)], &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		filesFound++
		lastFoundName = name[:len(name)-len(BadNameFlag)]
	}
	// search for the longest badname pattern match
	for charpos := len(name) - len(BadNameFlag); charpos > 0; charpos-- {
		//only use original cipher name and append assumed suffix (without badname flag)
		cNamePart := be.EncryptName(name[:charpos], iv)
		if be.longNames && len(cName) > NameMax {
			cNamePart = be.HashLongName(cName)
		}
		cNameBadReverse := cNamePart + name[charpos:len(name)-len(BadNameFlag)]
		err = syscallcompat.Fstatat(dirfd, cNameBadReverse, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			filesFound++
			lastFoundName = cNameBadReverse
		}
	}
	if filesFound == 1 {
		return lastFoundName, nil
	}
	// more than 1 possible file found, ignore
	return "", syscall.ENOENT
}

// Dir is like filepath.Dir but returns "" instead of ".".
func Dir(path string) string {
	d := filepath.Dir(path)
	if d == "." {
		return ""
	}
	return d
}
