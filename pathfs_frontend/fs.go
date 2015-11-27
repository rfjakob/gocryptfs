package pathfs_frontend

import (
	"encoding/base64"
	"fmt"
	"sync"
	"syscall"
	"os"
	"path/filepath"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
	"github.com/rfjakob/gocryptfs/cryptfs"
)

type FS struct {
	*cryptfs.CryptFS
	pathfs.FileSystem           // loopbackFileSystem, see go-fuse/fuse/pathfs/loopback.go
	backingDir           string // Backing directory, cipherdir
	// dirIVLock: Lock()ed if any "gocryptfs.diriv" file is modified
	// Readers must RLock() it to prevent them from seeing intermediate
	// states
	dirIVLock sync.RWMutex

}

// Encrypted FUSE overlay filesystem
func NewFS(key []byte, backing string, useOpenssl bool, plaintextNames bool) *FS {
	return &FS{
		CryptFS:    cryptfs.NewCryptFS(key, useOpenssl, plaintextNames),
		FileSystem: pathfs.NewLoopbackFileSystem(backing),
		backingDir:    backing,
	}
}

// GetBackingPath - get the absolute encrypted path of the backing file
// from the relative plaintext path "relPath"
func (fs *FS) getBackingPath(relPath string) (string, error) {
	encrypted, err := fs.encryptPath(relPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(fs.backingDir, encrypted), nil
}

func (fs *FS) GetAttr(name string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	cryptfs.Debug.Printf("FS.GetAttr('%s')\n", name)
	if fs.CryptFS.IsFiltered(name) {
		return nil, fuse.EPERM
	}
	cName, err := fs.encryptPath(name)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	a, status := fs.FileSystem.GetAttr(cName, context)
	if a == nil {
		cryptfs.Debug.Printf("FS.GetAttr failed: %s\n", status.String())
		return a, status
	}
	if a.IsRegular() {
		a.Size = fs.CipherSizeToPlainSize(a.Size)
	} else if a.IsSymlink() {
		target, _ := fs.Readlink(name, context)
		a.Size = uint64(len(target))
	}
	return a, status
}

func (fs *FS) OpenDir(dirName string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	cryptfs.Debug.Printf("OpenDir(%s)\n", dirName)
	cDirName, err := fs.encryptPath(dirName)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	cipherEntries, status := fs.FileSystem.OpenDir(cDirName, context)
	var plain []fuse.DirEntry
	if cipherEntries != nil {
		for i := range cipherEntries {
			cName := cipherEntries[i].Name
			if dirName == "" && cName == cryptfs.ConfDefaultName {
				// silently ignore "gocryptfs.conf" in the top level dir
				continue
			}
			if cName == cryptfs.DIRIV_FILENAME {
				// silently ignore "gocryptfs.diriv" everywhere
				continue
			}
			name, err := fs.decryptPath(cName)
			if err != nil {
				cryptfs.Warn.Printf("Invalid name \"%s\" in dir \"%s\": %s\n", cName, dirName, err)
				continue
			}
			cipherEntries[i].Name = name
			plain = append(plain, cipherEntries[i])
		}
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
	cryptfs.Debug.Printf("Open(%s)\n", path)
	if fs.CryptFS.IsFiltered(path) {
		return nil, fuse.EPERM
	}
	iflags, writeOnly := fs.mangleOpenFlags(flags)
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	f, err := os.OpenFile(cPath, iflags, 0666)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}

	return NewFile(f, writeOnly, fs.CryptFS), fuse.OK
}

func (fs *FS) Create(path string, flags uint32, mode uint32, context *fuse.Context) (fuseFile nodefs.File, code fuse.Status) {
	if fs.CryptFS.IsFiltered(path) {
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
	return NewFile(f, writeOnly, fs.CryptFS), fuse.OK
}

func (fs *FS) Chmod(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fs.FileSystem.Chmod(cPath, mode, context)
}

func (fs *FS) Chown(path string, uid uint32, gid uint32, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fs.FileSystem.Chown(cPath, uid, gid, context)
}

func (fs *FS) Mknod(path string, mode uint32, dev uint32, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fs.FileSystem.Mknod(cPath, mode, dev, context)
}

func (fs *FS) Truncate(path string, offset uint64, context *fuse.Context) (code fuse.Status) {
	cryptfs.Warn.Printf("Truncate of a closed file is not supported, returning ENOSYS\n")
	return fuse.ENOSYS
}

func (fs *FS) Utimens(path string, Atime *time.Time, Mtime *time.Time, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(path) {
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
	dst, status := fs.FileSystem.Readlink(cPath, context)
	if status != fuse.OK {
		return "", status
	}
	dstPlain, err := fs.decryptPath(dst)
	if err != nil {
		cryptfs.Warn.Printf("Failed decrypting symlink: %s\n", err.Error())
		return "", fuse.EIO
	}
	return dstPlain, status
}

func (fs *FS) Mkdir(relPath string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(relPath) {
		return fuse.EPERM
	}
	encPath, err := fs.getBackingPath(relPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	// Create directory
	fs.dirIVLock.Lock()
	defer fs.dirIVLock.Unlock()
	err = os.Mkdir(encPath, os.FileMode(mode))
	if err != nil {
		return fuse.ToStatus(err)
	}
	// Create gocryptfs.diriv inside
	err = fs.CryptFS.WriteDirIV(encPath)
	if err != nil {
		// This should not happen
		cryptfs.Warn.Printf("Creating %s in dir %s failed: %v\n", cryptfs.DIRIV_FILENAME, encPath, err)
		err2 := syscall.Rmdir(encPath)
		if err2 != nil {
			cryptfs.Warn.Printf("Mkdir: Rollback failed: %v\n", err2)
		}
		return fuse.ToStatus(err)
	}
	return fuse.OK
}

func (fs *FS) Unlink(path string, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fuse.ToStatus(syscall.Unlink(cPath))
}

func (fs *FS) Rmdir(name string, context *fuse.Context) (code fuse.Status) {
	encPath, err := fs.getBackingPath(name)
	if err != nil {
		return fuse.ToStatus(err)
	}

	// If the directory is not empty besides gocryptfs.diriv, do not even
	// attempt the dance around gocryptfs.diriv.
	fd, err := os.Open(encPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer fd.Close()
	list, err := fd.Readdirnames(10)
	if err != nil {
		return fuse.ToStatus(err)
	}
	if len(list) > 1 {
		return fuse.ToStatus(syscall.ENOTEMPTY)
	}

	// Move "gocryptfs.diriv" to the parent dir under name "gocryptfs.diriv.rmdir.INODENUMBER"
	var st syscall.Stat_t
	err = syscall.Fstat(int(fd.Fd()), &st)
	if err != nil {
		return fuse.ToStatus(err)
	}
	dirivPath := filepath.Join(encPath, cryptfs.DIRIV_FILENAME)
	parentDir := filepath.Dir(encPath)
	tmpName := fmt.Sprintf("gocryptfs.diriv.rmdir.%d", st.Ino)
	tmpDirivPath := filepath.Join(parentDir, tmpName)
	cryptfs.Debug.Printf("Rmdir: Renaming %s to %s\n", cryptfs.DIRIV_FILENAME, tmpDirivPath)
	fs.dirIVLock.Lock() // directory will be in an inconsistent state after the rename
	defer fs.dirIVLock.Unlock()
	err = os.Rename(dirivPath, tmpDirivPath)
	if err != nil {
		cryptfs.Warn.Printf("Rmdir: Renaming %s to %s failed: %v\n", cryptfs.DIRIV_FILENAME, tmpDirivPath, err)
		return fuse.ToStatus(err)
	}
	// Actual Rmdir
	err = syscall.Rmdir(encPath)
	if err != nil {
		// This can happen if another file in the directory was created in the
		// meantime, undo the rename
		err2 := os.Rename(tmpDirivPath, dirivPath)
		if err2 != nil {
			cryptfs.Warn.Printf("Rmdir: Rollback failed: %v\n", err2)
		}
		return fuse.ToStatus(err)
	}
	// Delete "gocryptfs.diriv.rmdir.INODENUMBER"
	err = syscall.Unlink(tmpDirivPath)
	if err != nil {
		cryptfs.Warn.Printf("Rmdir: Could not clean up %s: %v\n", tmpName, err)
	}

	return fuse.OK
}

func (fs *FS) Symlink(target string, linkName string, context *fuse.Context) (code fuse.Status) {
	cryptfs.Debug.Printf("Symlink(\"%s\", \"%s\")\n", target, linkName)
	if fs.CryptFS.IsFiltered(linkName) {
		return fuse.EPERM
	}
	cName, err := fs.encryptPath(linkName)
	if err != nil {
		return fuse.ToStatus(err)
	}

	cBinTarget := fs.CryptFS.EncryptBlock([]byte(target), 0, nil)
	cTarget := base64.URLEncoding.EncodeToString(cBinTarget)

	return fuse.ToStatus(os.Symlink(cTarget, cName))
}

func (fs *FS) Rename(oldPath string, newPath string, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(newPath) {
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
	return fs.FileSystem.Rename(cOldPath, cNewPath, context)
}

func (fs *FS) Link(oldPath string, newPath string, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(newPath) {
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
	if fs.CryptFS.IsFiltered(path) {
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
