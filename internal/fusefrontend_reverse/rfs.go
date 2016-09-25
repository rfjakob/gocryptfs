package fusefrontend_reverse

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

const (
	DirIVMode = syscall.S_IFREG | 0400
)

type reverseFS struct {
	// Embed pathfs.defaultFileSystem for a ENOSYS implementation of all methods
	pathfs.FileSystem
	// pathfs.loopbackFileSystem, see go-fuse/fuse/pathfs/loopback.go
	loopbackfs pathfs.FileSystem
	// Stores configuration arguments
	args fusefrontend.Args
	// Filename encryption helper
	nameTransform *nametransform.NameTransform
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// Inode number generator
	inoGen *inoGenT
	// Maps backing files device+inode pairs to user-facing unique inode numbers
	inoMap map[devIno]uint64
	// Protects map access
	inoMapLock sync.Mutex
}

// Encrypted FUSE overlay filesystem
func NewFS(args fusefrontend.Args) *reverseFS {
	cryptoCore := cryptocore.New(args.Masterkey, args.CryptoBackend, contentenc.DefaultIVBits)
	contentEnc := contentenc.New(cryptoCore, contentenc.DefaultBS)
	nameTransform := nametransform.New(cryptoCore, args.LongNames)

	return &reverseFS{
		// pathfs.defaultFileSystem returns ENOSYS for all operations
		FileSystem:    pathfs.NewDefaultFileSystem(),
		loopbackfs:    pathfs.NewLoopbackFileSystem(args.Cipherdir),
		args:          args,
		nameTransform: nameTransform,
		contentEnc:    contentEnc,
		inoGen:        NewInoGen(),
		inoMap:        map[devIno]uint64{},
	}
}

// relDir is identical to filepath.Dir excepts that it returns "" when
// filepath.Dir would return ".".
// In the FUSE API, the root directory is called "", and we actually want that.
func relDir(path string) string {
	dir := filepath.Dir(path)
	if dir == "." {
		return ""
	}
	return dir
}

// dirIVAttr handles GetAttr requests for the virtual gocryptfs.diriv files.
func (rfs *reverseFS) dirIVAttr(relPath string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	cDir := relDir(relPath)
	dir, err := rfs.decryptPath(cDir)
	if err != nil {
		fmt.Printf("decrypt err %q\n", cDir)
		return nil, fuse.ToStatus(err)
	}
	// Does the parent dir exist?
	a, status := rfs.loopbackfs.GetAttr(dir, context)
	if !status.Ok() {
		fmt.Printf("missing parent\n")
		return nil, status
	}
	// Is it a dir at all?
	if !a.IsDir() {
		fmt.Printf("not isdir\n")
		return nil, fuse.ENOTDIR
	}
	// Does the user have execute permissions?
	if a.Mode&syscall.S_IXUSR == 0 {
		fmt.Printf("not exec")
		return nil, fuse.EPERM
	}
	// All good. Let's fake the file. We use the timestamps from the parent dir.
	a.Mode = DirIVMode
	a.Size = nametransform.DirIVLen
	a.Nlink = 1
	a.Ino = rfs.inoGen.next()

	return a, fuse.OK
}

// isDirIV determines if the path points to a gocryptfs.diriv file
func isDirIV(relPath string) bool {
	return filepath.Base(relPath) == nametransform.DirIVFilename
}

// isNameFile determines if the path points to a gocryptfs.longname.*.name
// file
func isNameFile(relPath string) bool {
	fileType := nametransform.NameType(filepath.Base(relPath))
	return fileType == nametransform.LongNameFilename
}

func (rfs *reverseFS) inoAwareStat(relPlainPath string) (*fuse.Attr, fuse.Status) {
	absPath, err := rfs.abs(relPlainPath, nil)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	var fi os.FileInfo
	if relPlainPath == "" {
		// Look through symlinks for the root dir
		fi, err = os.Stat(absPath)
	} else {
		fi, err = os.Lstat(absPath)
	}
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	// The file has hard links. We have to give it a stable inode number so
	// tar or rsync can find them.
	if fi.Mode().IsRegular() && st.Nlink > 1 {
		di := devIno{st.Dev, st.Ino}
		rfs.inoMapLock.Lock()
		stableIno := rfs.inoMap[di]
		if stableIno == 0 {
			rfs.inoMap[di] = rfs.inoGen.next()
		}
		rfs.inoMapLock.Unlock()
		st.Ino = stableIno
	} else {
		st.Ino = rfs.inoGen.next()
	}
	a := &fuse.Attr{}
	a.FromStat(st)
	return a, fuse.OK
}

// GetAttr - FUSE call
func (rfs *reverseFS) GetAttr(relPath string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	if relPath == configfile.ConfDefaultName {
		return rfs.inoAwareStat(configfile.ConfReverseName)
	}
	if rfs.isFiltered(relPath) {
		return nil, fuse.EPERM
	}

	// Handle virtual files
	var f nodefs.File
	var status fuse.Status
	virtual := false
	if isDirIV(relPath) {
		virtual = true
		f, status = rfs.newDirIVFile(relPath)
	}
	if isNameFile(relPath) {
		virtual = true
		f, status = rfs.newNameFile(relPath)
	}
	if virtual {
		if !status.Ok() {
			fmt.Printf("GetAttr %q: newXFile failed: %v\n", relPath, status)
			return nil, status
		}
		var a fuse.Attr
		status = f.GetAttr(&a)
		return &a, status
	}

	cPath, err := rfs.decryptPath(relPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	a, status := rfs.inoAwareStat(cPath)
	if !status.Ok() {
		return nil, status
	}
	// Calculate encrypted file size
	if a.IsRegular() {
		a.Size = rfs.contentEnc.PlainSizeToCipherSize(a.Size)
	}
	return a, fuse.OK
}

// Access - FUSE call
func (rfs *reverseFS) Access(relPath string, mode uint32, context *fuse.Context) fuse.Status {
	if isDirIV(relPath) {
		return fuse.OK
	}
	if rfs.isFiltered(relPath) {
		return fuse.EPERM
	}
	absPath, err := rfs.abs(rfs.decryptPath(relPath))
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fuse.ToStatus(syscall.Access(absPath, mode))
}

// Open - FUSE call
func (rfs *reverseFS) Open(relPath string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	if relPath == configfile.ConfDefaultName {
		// gocryptfs.conf maps to .gocryptfs.reverse.conf in the plaintext directory
		return rfs.loopbackfs.Open(configfile.ConfReverseName, flags, context)
	}
	if isDirIV(relPath) {
		return rfs.newDirIVFile(relPath)
	}
	if isNameFile(relPath) {
		return rfs.newNameFile(relPath)
	}
	if rfs.isFiltered(relPath) {
		return nil, fuse.EPERM
	}
	return rfs.NewFile(relPath, flags)
}

// OpenDir - FUSE readdir call
func (rfs *reverseFS) OpenDir(cipherPath string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	relPath, err := rfs.decryptPath(cipherPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Read plaintext dir
	entries, status := rfs.loopbackfs.OpenDir(relPath, context)
	if entries == nil {
		return nil, status
	}
	// Allocate maximum possible number of virtual files.
	// If all files have long names we need a virtual ".name" file for each,
	// plus one for gocryptfs.diriv.
	virtualFiles := make([]fuse.DirEntry, len(entries)+1)
	// Virtual gocryptfs.diriv file
	virtualFiles[0] = fuse.DirEntry{
		Mode: syscall.S_IFREG | 0400,
		Name: nametransform.DirIVFilename,
	}
	// Actually used entries
	nVirtual := 1

	// Encrypt names
	dirIV := derivePathIV(cipherPath)
	for i := range entries {
		var cName string
		// ".gocryptfs.reverse.conf" in the root directory is mapped to "gocryptfs.conf"
		if cipherPath == "" && entries[i].Name == configfile.ConfReverseName {
			cName = configfile.ConfDefaultName
		} else {
			cName = rfs.nameTransform.EncryptName(entries[i].Name, dirIV)
			if len(cName) > syscall.NAME_MAX {
				cName = nametransform.HashLongName(cName)
				dotNameFile := fuse.DirEntry{
					Mode: syscall.S_IFREG | 0600,
					Name: cName + nametransform.LongNameSuffix,
				}
				virtualFiles[nVirtual] = dotNameFile
				nVirtual++
			}
		}
		entries[i].Name = cName
	}
	entries = append(entries, virtualFiles[:nVirtual]...)
	return entries, fuse.OK
}

// StatFs - FUSE call
func (rfs *reverseFS) StatFs(name string) *fuse.StatfsOut {
	return rfs.loopbackfs.StatFs(name)
}

// Readlink - FUSE call
func (rfs *reverseFS) Readlink(cipherPath string, context *fuse.Context) (string, fuse.Status) {
	absPath, err := rfs.abs(rfs.decryptPath(cipherPath))
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	plainTarget, err := os.Readlink(absPath)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	if rfs.args.PlaintextNames {
		return plainTarget, fuse.OK
	}
	nonce := derivePathIV(cipherPath)
	// Symlinks are encrypted like file contents and base64-encoded
	cBinTarget := rfs.contentEnc.EncryptBlock([]byte(plainTarget), 0, nil, contentenc.ExternalNonce, nonce)
	cTarget := base64.URLEncoding.EncodeToString(cBinTarget)
	return cTarget, fuse.OK
}
