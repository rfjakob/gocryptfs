package nametransform

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
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
// If deterministicNames is set it returns an all-zero slice.
func (n *NameTransform) ReadDirIVAt(dirfd int) (iv []byte, err error) {
	if n.deterministicNames {
		return make([]byte, DirIVLen), nil
	}
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
