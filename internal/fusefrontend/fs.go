package fusefrontend

// FUSE operations on paths

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/toggledlog"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/configfile"
)

type FS struct {
	pathfs.FileSystem      // loopbackFileSystem, see go-fuse/fuse/pathfs/loopback.go
	args              Args // Stores configuration arguments
	// dirIVLock: Lock()ed if any "gocryptfs.diriv" file is modified
	// Readers must RLock() it to prevent them from seeing intermediate
	// states
	dirIVLock sync.RWMutex
	// Filename encryption helper
	nameTransform *nametransform.NameTransform
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
}

// Encrypted FUSE overlay filesystem
func NewFS(args Args) *FS {

	cryptoCore := cryptocore.New(args.Masterkey, args.OpenSSL, args.GCMIV128)
	contentEnc := contentenc.New(cryptoCore, contentenc.DefaultBS)
	nameTransform := nametransform.New(cryptoCore, args.EMENames)

	return &FS{
		FileSystem: pathfs.NewLoopbackFileSystem(args.Cipherdir),
		args:       args,
		nameTransform: nameTransform,
		contentEnc: contentEnc,
	}
}

// GetBackingPath - get the absolute encrypted path of the backing file
// from the relative plaintext path "relPath"
func (fs *FS) getBackingPath(relPath string) (string, error) {
	cPath, err := fs.encryptPath(relPath)
	if err != nil {
		return "", err
	}
	cAbsPath := filepath.Join(fs.args.Cipherdir, cPath)
	toggledlog.Debug.Printf("getBackingPath: %s + %s -> %s", fs.args.Cipherdir, relPath, cAbsPath)
	return cAbsPath, nil
}

func (fs *FS) GetAttr(name string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	toggledlog.Debug.Printf("FS.GetAttr('%s')", name)
	if fs.isFiltered(name) {
		return nil, fuse.EPERM
	}
	cName, err := fs.encryptPath(name)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	a, status := fs.FileSystem.GetAttr(cName, context)
	if a == nil {
		toggledlog.Debug.Printf("FS.GetAttr failed: %s", status.String())
		return a, status
	}
	if a.IsRegular() {
		a.Size = fs.contentEnc.CipherSizeToPlainSize(a.Size)
	} else if a.IsSymlink() {
		target, _ := fs.Readlink(name, context)
		a.Size = uint64(len(target))
	}
	return a, status
}

func (fs *FS) OpenDir(dirName string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	toggledlog.Debug.Printf("OpenDir(%s)", dirName)
	cDirName, err := fs.encryptPath(dirName)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Read ciphertext directory
	cipherEntries, status := fs.FileSystem.OpenDir(cDirName, context)
	if cipherEntries == nil {
		return nil, status
	}
	// Get DirIV (stays nil if DirIV if off)
	var cachedIV []byte
	if fs.args.DirIV {
		// Read the DirIV once and use it for all later name decryptions
		cDirAbsPath := filepath.Join(fs.args.Cipherdir, cDirName)
		cachedIV, err = fs.nameTransform.ReadDirIV(cDirAbsPath)
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
	}
	// Filter and decrypt filenames
	var plain []fuse.DirEntry
	for i := range cipherEntries {
		cName := cipherEntries[i].Name
		if dirName == "" && cName == configfile.ConfDefaultName {
			// silently ignore "gocryptfs.conf" in the top level dir
			continue
		}
		if fs.args.DirIV && cName == nametransform.DirIVFilename {
			// silently ignore "gocryptfs.diriv" everywhere if dirIV is enabled
			continue
		}
		var name string = cName
		if !fs.args.PlaintextNames {
			name, err = fs.nameTransform.DecryptName(cName, cachedIV)
			if err != nil {
				toggledlog.Warn.Printf("Invalid name \"%s\" in dir \"%s\": %s", cName, cDirName, err)
				continue
			}
		}
		cipherEntries[i].Name = name
		plain = append(plain, cipherEntries[i])
	}
	return plain, status
}

// We always need read access to do read-modify-write cycles
func (fs *FS) mangleOpenFlags(flags uint32) (newFlags int, writeOnly bool) {
	newFlags = int(flags)
	if newFlags&os.O_WRONLY > 0 {
		writeOnly = true
		newFlags = newFlags ^ os.O_WRONLY | os.O_RDWR
	}
	// We also cannot open the file in append mode, we need to seek back for RMW
	newFlags = newFlags &^ os.O_APPEND

	return newFlags, writeOnly
}

func (fs *FS) Open(path string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	if fs.isFiltered(path) {
		return nil, fuse.EPERM
	}
	iflags, writeOnly := fs.mangleOpenFlags(flags)
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		toggledlog.Debug.Printf("Open: getBackingPath: %v", err)
		return nil, fuse.ToStatus(err)
	}
	toggledlog.Debug.Printf("Open: %s", cPath)
	f, err := os.OpenFile(cPath, iflags, 0666)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}

	return NewFile(f, writeOnly, fs.contentEnc), fuse.OK
}

func (fs *FS) Create(path string, flags uint32, mode uint32, context *fuse.Context) (fuseFile nodefs.File, code fuse.Status) {
	if fs.isFiltered(path) {
		return nil, fuse.EPERM
	}
	iflags, writeOnly := fs.mangleOpenFlags(flags)
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	f, err := os.OpenFile(cPath, iflags|os.O_CREATE, os.FileMode(mode))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	return NewFile(f, writeOnly, fs.contentEnc), fuse.OK
}

func (fs *FS) Chmod(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fs.FileSystem.Chmod(cPath, mode, context)
}

func (fs *FS) Chown(path string, uid uint32, gid uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fs.FileSystem.Chown(cPath, uid, gid, context)
}

func (fs *FS) Mknod(path string, mode uint32, dev uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fs.FileSystem.Mknod(cPath, mode, dev, context)
}

var truncateWarned bool

func (fs *FS) Truncate(path string, offset uint64, context *fuse.Context) (code fuse.Status) {
	// Only warn once
	if !truncateWarned {
		toggledlog.Warn.Printf("truncate(2) is not supported, returning ENOSYS - use ftruncate(2)")
		truncateWarned = true
	}
	return fuse.ENOSYS
}

func (fs *FS) Utimens(path string, Atime *time.Time, Mtime *time.Time, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fs.FileSystem.Utimens(cPath, Atime, Mtime, context)
}

func (fs *FS) Readlink(path string, context *fuse.Context) (out string, status fuse.Status) {
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	cTarget, status := fs.FileSystem.Readlink(cPath, context)
	if status != fuse.OK {
		return "", status
	}
	// Old filesystem: symlinks are encrypted like paths (CBC)
	if !fs.args.DirIV {
		target, err := fs.decryptPath(cTarget)
		if err != nil {
			toggledlog.Warn.Printf("Readlink: CBC decryption failed: %v", err)
			return "", fuse.EIO
		}
		return target, fuse.OK
	}
	// Since gocryptfs v0.5 symlinks are encrypted like file contents (GCM)
	cBinTarget, err := base64.URLEncoding.DecodeString(cTarget)
	if err != nil {
		toggledlog.Warn.Printf("Readlink: %v", err)
		return "", fuse.EIO
	}
	target, err := fs.contentEnc.DecryptBlock([]byte(cBinTarget), 0, nil)
	if err != nil {
		toggledlog.Warn.Printf("Readlink: %v", err)
		return "", fuse.EIO
	}
	return string(target), fuse.OK
}

func (fs *FS) Unlink(path string, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fuse.ToStatus(syscall.Unlink(cPath))
}

func (fs *FS) Symlink(target string, linkName string, context *fuse.Context) (code fuse.Status) {
	toggledlog.Debug.Printf("Symlink(\"%s\", \"%s\")", target, linkName)
	if fs.isFiltered(linkName) {
		return fuse.EPERM
	}
	cPath, err := fs.getBackingPath(linkName)
	if err != nil {
		return fuse.ToStatus(err)
	}
	// Old filesystem: symlinks are encrypted like paths (CBC)
	if !fs.args.DirIV {
		cTarget, err := fs.encryptPath(target)
		if err != nil {
			toggledlog.Warn.Printf("Symlink: BUG: we should not get an error here: %v", err)
			return fuse.ToStatus(err)
		}
		err = os.Symlink(cTarget, cPath)
		return fuse.ToStatus(err)
	}
	// Since gocryptfs v0.5 symlinks are encrypted like file contents (GCM)
	cBinTarget := fs.contentEnc.EncryptBlock([]byte(target), 0, nil)
	cTarget := base64.URLEncoding.EncodeToString(cBinTarget)

	err = os.Symlink(cTarget, cPath)
	toggledlog.Debug.Printf("Symlink: os.Symlink(%s, %s) = %v", cTarget, cPath, err)
	return fuse.ToStatus(err)
}

func (fs *FS) Rename(oldPath string, newPath string, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(newPath) {
		return fuse.EPERM
	}
	cOldPath, err := fs.getBackingPath(oldPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	cNewPath, err := fs.getBackingPath(newPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	// The Rename may cause a directory to take the place of another directory.
	// That directory may still be in the DirIV cache, clear it.
	fs.nameTransform.DirIVCache.Clear()

	err = os.Rename(cOldPath, cNewPath)

	if lerr, ok := err.(*os.LinkError); ok && lerr.Err == syscall.ENOTEMPTY {
		// If an empty directory is overwritten we will always get
		// ENOTEMPTY as the "empty" directory will still contain gocryptfs.diriv.
		// Handle that case by removing the target directory and trying again.
		toggledlog.Debug.Printf("Rename: Handling ENOTEMPTY")
		if fs.Rmdir(newPath, context) == fuse.OK {
			err = os.Rename(cOldPath, cNewPath)
		}
	}

	return fuse.ToStatus(err)
}

func (fs *FS) Link(oldPath string, newPath string, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(newPath) {
		return fuse.EPERM
	}
	cOldPath, err := fs.getBackingPath(oldPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	cNewPath, err := fs.getBackingPath(newPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fuse.ToStatus(os.Link(cOldPath, cNewPath))
}

func (fs *FS) Access(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fuse.ToStatus(syscall.Access(cPath, mode))
}

func (fs *FS) GetXAttr(name string, attr string, context *fuse.Context) ([]byte, fuse.Status) {
	return nil, fuse.ENOSYS
}

func (fs *FS) SetXAttr(name string, attr string, data []byte, flags int, context *fuse.Context) fuse.Status {
	return fuse.ENOSYS
}

func (fs *FS) ListXAttr(name string, context *fuse.Context) ([]string, fuse.Status) {
	return nil, fuse.ENOSYS
}

func (fs *FS) RemoveXAttr(name string, attr string, context *fuse.Context) fuse.Status {
	return fuse.ENOSYS
}
