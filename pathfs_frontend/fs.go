package pathfs_frontend

import (
	"fmt"
	"sync"
	"syscall"
	"io/ioutil"
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
	pathfs.FileSystem        // loopbackFileSystem, see go-fuse/fuse/pathfs/loopback.go
	backing           string // Backing directory
	dirivLock sync.RWMutex   // Global lock that is taken if any "gocryptfs.diriv" file is modified
}

// Encrypted FUSE overlay filesystem
func NewFS(key []byte, backing string, useOpenssl bool, plaintextNames bool) *FS {
	return &FS{
		CryptFS:    cryptfs.NewCryptFS(key, useOpenssl, plaintextNames),
		FileSystem: pathfs.NewLoopbackFileSystem(backing),
		backing:    backing,
	}
}

// GetPath - get the absolute encrypted path of the backing file
// from the relative plaintext path "relPath"
func (fs *FS) GetPath(relPath string) string {
	return filepath.Join(fs.backing, fs.EncryptPath(relPath))
}

func (fs *FS) GetAttr(name string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	cryptfs.Debug.Printf("FS.GetAttr('%s')\n", name)
	if fs.CryptFS.IsFiltered(name) {
		return nil, fuse.EPERM
	}
	cName := fs.EncryptPath(name)
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
	cipherEntries, status := fs.FileSystem.OpenDir(fs.EncryptPath(dirName), context)
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
			name, err := fs.DecryptPath(cName)
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
	f, err := os.OpenFile(fs.GetPath(path), iflags, 0666)
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
	f, err := os.OpenFile(fs.GetPath(path), iflags|os.O_CREATE, os.FileMode(mode))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	return NewFile(f, writeOnly, fs.CryptFS), fuse.OK
}

func (fs *FS) Chmod(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(path) {
		return fuse.EPERM
	}
	return fs.FileSystem.Chmod(fs.EncryptPath(path), mode, context)
}

func (fs *FS) Chown(path string, uid uint32, gid uint32, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(path) {
		return fuse.EPERM
	}
	return fs.FileSystem.Chown(fs.EncryptPath(path), uid, gid, context)
}

func (fs *FS) Mknod(name string, mode uint32, dev uint32, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(name) {
		return fuse.EPERM
	}
	return fs.FileSystem.Mknod(fs.EncryptPath(name), mode, dev, context)
}

func (fs *FS) Truncate(path string, offset uint64, context *fuse.Context) (code fuse.Status) {
	cryptfs.Warn.Printf("Truncate of a closed file is not supported, returning ENOSYS\n")
	return fuse.ENOSYS
}

func (fs *FS) Utimens(path string, Atime *time.Time, Mtime *time.Time, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(path) {
		return fuse.EPERM
	}
	return fs.FileSystem.Utimens(fs.EncryptPath(path), Atime, Mtime, context)
}

func (fs *FS) Readlink(name string, context *fuse.Context) (out string, status fuse.Status) {
	dst, status := fs.FileSystem.Readlink(fs.EncryptPath(name), context)
	if status != fuse.OK {
		return "", status
	}
	dstPlain, err := fs.DecryptPath(dst)
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
	encPath := fs.GetPath(relPath)
	diriv := cryptfs.RandBytes(cryptfs.DIRIV_LEN)
	dirivPath := filepath.Join(encPath, cryptfs.DIRIV_FILENAME)
	// Create directory
	err := os.Mkdir(encPath, os.FileMode(mode))
	if err != nil {
		return fuse.ToStatus(err)
	}
	// Create gocryptfs.diriv inside
	// 0444 permissions: the file is not secret but should not be written to
	err = ioutil.WriteFile(dirivPath, diriv, 0444)
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

func (fs *FS) Unlink(name string, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(name) {
		return fuse.EPERM
	}
	cName := fs.EncryptPath(name)
	code = fs.FileSystem.Unlink(cName, context)
	if code != fuse.OK {
		cryptfs.Debug.Printf("Unlink failed on %s [%s], code=%s\n", name, cName, code.String())
	}
	return code
}

func (fs *FS) Rmdir(name string, context *fuse.Context) (code fuse.Status) {
	encPath := fs.GetPath(name)

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
	fs.dirivLock.Lock() // directory will be in an inconsistent state after the rename
	defer fs.dirivLock.Unlock()
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

func (fs *FS) Symlink(pointedTo string, linkName string, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(linkName) {
		return fuse.EPERM
	}
	// TODO symlink encryption
	cryptfs.Debug.Printf("Symlink(\"%s\", \"%s\")\n", pointedTo, linkName)
	return fs.FileSystem.Symlink(fs.EncryptPath(pointedTo), fs.EncryptPath(linkName), context)
}

func (fs *FS) Rename(oldPath string, newPath string, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(newPath) {
		return fuse.EPERM
	}
	return fs.FileSystem.Rename(fs.EncryptPath(oldPath), fs.EncryptPath(newPath), context)
}

func (fs *FS) Link(orig string, newName string, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(newName) {
		return fuse.EPERM
	}
	return fs.FileSystem.Link(fs.EncryptPath(orig), fs.EncryptPath(newName), context)
}

func (fs *FS) Access(name string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.CryptFS.IsFiltered(name) {
		return fuse.EPERM
	}
	return fs.FileSystem.Access(fs.EncryptPath(name), mode, context)
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
