package pathfs_frontend

import (
	"os"
	"path/filepath"
	"time"
	"fmt"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
	"github.com/rfjakob/gocryptfs/cryptfs"
)

type FS struct {
	*cryptfs.CryptFS
	pathfs.FileSystem    // loopbackFileSystem
	backing string       // Backing directory
}

// Encrypted FUSE overlay filesystem
func NewFS(key []byte, backing string, useOpenssl bool) *FS {
	return &FS{
		CryptFS:     cryptfs.NewCryptFS(key, useOpenssl),
		FileSystem:  pathfs.NewLoopbackFileSystem(backing),
		backing:     backing,

	}
}

// GetPath - get the absolute path of the backing file
func (fs *FS) GetPath(relPath string) string {
	return filepath.Join(fs.backing, fs.EncryptPath(relPath))
}

func (fs *FS) GetAttr(name string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	cryptfs.Debug.Printf("FS.GetAttr('%s')\n", name)
	cName := fs.EncryptPath(name)
	a, status := fs.FileSystem.GetAttr(cName, context)
	if a == nil {
		cryptfs.Debug.Printf("FS.GetAttr failed: %s\n", status.String())
		return a, status
	}
	if a.IsRegular() {
		a.Size = fs.PlainSize(a.Size)
	} else if a.IsSymlink() {
		target, _ := fs.Readlink(name, context)
		a.Size = uint64(len(target))
	}
	return a, status
}

func (fs *FS) OpenDir(dirName string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	cryptfs.Debug.Printf("OpenDir(%s)\n", dirName)
	cipherEntries, status := fs.FileSystem.OpenDir(fs.EncryptPath(dirName), context);
	var plain []fuse.DirEntry
	if cipherEntries != nil {
		for i := range cipherEntries {
			cName := cipherEntries[i].Name
			name, err := fs.DecryptPath(cName)
			if err != nil {
				if dirName == "" && cName == cryptfs.ConfDefaultName {
					// Silently ignore "gocryptfs.conf" in the top level dir
					continue
				}
				fmt.Printf("Invalid name \"%s\" in dir \"%s\": %s\n", cName, name, err)
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
	if newFlags & os.O_WRONLY > 0 {
		writeOnly = true
		newFlags = newFlags ^ os.O_WRONLY | os.O_RDWR
	}
	// We also cannot open the file in append mode, we need to seek back for RMW
	newFlags = newFlags &^ os.O_APPEND

	return newFlags, writeOnly
}

func (fs *FS) Open(name string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	cryptfs.Debug.Printf("Open(%s)\n", name)

	iflags, writeOnly := fs.mangleOpenFlags(flags)
	f, err := os.OpenFile(fs.GetPath(name), iflags, 0666)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}

	return NewFile(f, writeOnly, fs.CryptFS), fuse.OK
}

func (fs *FS) Create(path string, flags uint32, mode uint32, context *fuse.Context) (fuseFile nodefs.File, code fuse.Status) {
	iflags, writeOnly := fs.mangleOpenFlags(flags)
	f, err := os.OpenFile(fs.GetPath(path), iflags|os.O_CREATE, os.FileMode(mode))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	return NewFile(f, writeOnly, fs.CryptFS), fuse.OK
}

func (fs *FS) Chmod(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	return fs.FileSystem.Chmod(fs.EncryptPath(path), mode, context)
}

func (fs *FS) Chown(path string, uid uint32, gid uint32, context *fuse.Context) (code fuse.Status) {
	return fs.FileSystem.Chown(fs.EncryptPath(path), uid, gid, context)
}

func (fs *FS) Mknod(name string, mode uint32, dev uint32, context *fuse.Context) (code fuse.Status) {
	return fs.FileSystem.Mknod(fs.EncryptPath(name), mode, dev, context)
}

func (fs *FS) Truncate(path string, offset uint64, context *fuse.Context) (code fuse.Status) {
	return fs.FileSystem.Truncate(fs.EncryptPath(path), offset, context)
}

func (fs *FS) Utimens(path string, Atime *time.Time, Mtime *time.Time, context *fuse.Context) (code fuse.Status) {
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

func (fs *FS) Mkdir(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	return fs.FileSystem.Mkdir(fs.EncryptPath(path), mode, context)
}

func (fs *FS) Unlink(name string, context *fuse.Context) (code fuse.Status) {
	cName := fs.EncryptPath(name)
	code = fs.FileSystem.Unlink(cName, context)
	if code != fuse.OK {
		cryptfs.Notice.Printf("Unlink failed on %s [%s], code=%s\n", name, cName, code.String())
	}
	return code
}

func (fs *FS) Rmdir(name string, context *fuse.Context) (code fuse.Status) {
	return fs.FileSystem.Rmdir(fs.EncryptPath(name), context)
}

func (fs *FS) Symlink(pointedTo string, linkName string, context *fuse.Context) (code fuse.Status) {
	// TODO symlink encryption
	cryptfs.Debug.Printf("Symlink(\"%s\", \"%s\")\n", pointedTo, linkName)
	return fs.FileSystem.Symlink(fs.EncryptPath(pointedTo), fs.EncryptPath(linkName), context)
}

func (fs *FS) Rename(oldPath string, newPath string, context *fuse.Context) (codee fuse.Status) {
	return fs.FileSystem.Rename(fs.EncryptPath(oldPath), fs.EncryptPath(newPath), context)
}

func (fs *FS) Link(orig string, newName string, context *fuse.Context) (code fuse.Status) {
	return fs.FileSystem.Link(fs.EncryptPath(orig), fs.EncryptPath(newName), context)
}

func (fs *FS) Access(name string, mode uint32, context *fuse.Context) (code fuse.Status) {
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
