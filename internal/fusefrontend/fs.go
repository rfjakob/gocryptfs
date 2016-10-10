// Package fusefrontend interfaces directly with the go-fuse library.
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

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// FS implements the go-fuse virtual filesystem interface.
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

var _ pathfs.FileSystem = &FS{} // Verify that interface is implemented.

// NewFS returns a new encrypted FUSE overlay filesystem.
func NewFS(args Args) *FS {
	cryptoCore := cryptocore.New(args.Masterkey, args.CryptoBackend, contentenc.DefaultIVBits)
	contentEnc := contentenc.New(cryptoCore, contentenc.DefaultBS)
	nameTransform := nametransform.New(cryptoCore, args.LongNames)

	return &FS{
		FileSystem:    pathfs.NewLoopbackFileSystem(args.Cipherdir),
		args:          args,
		nameTransform: nameTransform,
		contentEnc:    contentEnc,
	}
}

// GetAttr implements pathfs.Filesystem.
func (fs *FS) GetAttr(name string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	tlog.Debug.Printf("FS.GetAttr('%s')", name)
	if fs.isFiltered(name) {
		return nil, fuse.EPERM
	}
	cName, err := fs.encryptPath(name)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	a, status := fs.FileSystem.GetAttr(cName, context)
	if a == nil {
		tlog.Debug.Printf("FS.GetAttr failed: %s", status.String())
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

// Open implements pathfs.Filesystem.
func (fs *FS) Open(path string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	if fs.isFiltered(path) {
		return nil, fuse.EPERM
	}
	iflags, writeOnly := fs.mangleOpenFlags(flags)
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		tlog.Debug.Printf("Open: getBackingPath: %v", err)
		return nil, fuse.ToStatus(err)
	}
	tlog.Debug.Printf("Open: %s", cPath)
	f, err := os.OpenFile(cPath, iflags, 0666)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}

	return NewFile(f, writeOnly, fs.contentEnc)
}

// Create implements pathfs.Filesystem.
func (fs *FS) Create(path string, flags uint32, mode uint32, context *fuse.Context) (fuseFile nodefs.File, code fuse.Status) {
	if fs.isFiltered(path) {
		return nil, fuse.EPERM
	}
	iflags, writeOnly := fs.mangleOpenFlags(flags)
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}

	var fd *os.File
	cName := filepath.Base(cPath)

	// Handle long file name
	if nametransform.IsLongContent(cName) {
		var dirfd *os.File
		dirfd, err = os.Open(filepath.Dir(cPath))
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
		defer dirfd.Close()

		// Create ".name"
		err = fs.nameTransform.WriteLongName(dirfd, cName, path)
		if err != nil {
			return nil, fuse.ToStatus(err)
		}

		// Create content
		var fdRaw int
		fdRaw, err = syscallcompat.Openat(int(dirfd.Fd()), cName, iflags|os.O_CREATE, mode)
		if err != nil {
			nametransform.DeleteLongName(dirfd, cName)
			return nil, fuse.ToStatus(err)
		}
		fd = os.NewFile(uintptr(fdRaw), cName)
	} else {
		// Normal (short) file name
		fd, err = os.OpenFile(cPath, iflags|os.O_CREATE, os.FileMode(mode))
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
	}
	// Set owner
	if fs.args.PreserveOwner {
		err = fd.Chown(int(context.Owner.Uid), int(context.Owner.Gid))
		if err != nil {
			tlog.Warn.Printf("Create: Chown failed: %v", err)
		}
	}
	return NewFile(fd, writeOnly, fs.contentEnc)
}

// Chmod implements pathfs.Filesystem.
func (fs *FS) Chmod(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	// os.Chmod goes through the "syscallMode" translation function that messes
	// up the suid and sgid bits. So use syscall.Chmod directly.
	err = syscall.Chmod(cPath, mode)
	return fuse.ToStatus(err)
}

// Chown implements pathfs.Filesystem.
func (fs *FS) Chown(path string, uid uint32, gid uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fuse.ToStatus(os.Lchown(cPath, int(uid), int(gid)))
}

// Mknod implements pathfs.Filesystem.
func (fs *FS) Mknod(path string, mode uint32, dev uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}

	// Handle long file name
	cName := filepath.Base(cPath)
	if nametransform.IsLongContent(cName) {
		dirfd, err := os.Open(filepath.Dir(cPath))
		if err != nil {
			return fuse.ToStatus(err)
		}
		defer dirfd.Close()

		// Create ".name"
		err = fs.nameTransform.WriteLongName(dirfd, cName, path)
		if err != nil {
			return fuse.ToStatus(err)
		}

		// Create device node
		err = syscallcompat.Mknodat(int(dirfd.Fd()), cName, uint32(mode), int(dev))
		if err != nil {
			nametransform.DeleteLongName(dirfd, cName)
		}

		return fuse.ToStatus(err)
	}

	return fs.FileSystem.Mknod(cPath, mode, dev, context)
}

// Truncate implements pathfs.Filesystem.
// Support truncate(2) by opening the file and calling ftruncate(2)
// While the glibc "truncate" wrapper seems to always use ftruncate, fsstress from
// xfstests uses this a lot by calling "truncate64" directly.
func (fs *FS) Truncate(path string, offset uint64, context *fuse.Context) (code fuse.Status) {
	file, code := fs.Open(path, uint32(os.O_RDWR), context)
	if code != fuse.OK {
		return code
	}
	code = file.Truncate(offset)
	file.Release()
	return code
}

// Utimens implements pathfs.Filesystem.
func (fs *FS) Utimens(path string, a *time.Time, m *time.Time, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fs.FileSystem.Utimens(cPath, a, m, context)
}

// StatFs implements pathfs.Filesystem.
func (fs *FS) StatFs(path string) *fuse.StatfsOut {
	if fs.isFiltered(path) {
		return nil
	}
	cPath, err := fs.encryptPath(path)
	if err != nil {
		return nil
	}
	return fs.FileSystem.StatFs(cPath)
}

// Readlink implements pathfs.Filesystem.
func (fs *FS) Readlink(path string, context *fuse.Context) (out string, status fuse.Status) {
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	cTarget, err := os.Readlink(cPath)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	if fs.args.PlaintextNames {
		return cTarget, fuse.OK
	}
	// Symlinks are encrypted like file contents (GCM) and base64-encoded
	cBinTarget, err := base64.URLEncoding.DecodeString(cTarget)
	if err != nil {
		tlog.Warn.Printf("Readlink: %v", err)
		return "", fuse.EIO
	}
	target, err := fs.contentEnc.DecryptBlock([]byte(cBinTarget), 0, nil)
	if err != nil {
		tlog.Warn.Printf("Readlink: %v", err)
		return "", fuse.EIO
	}
	return string(target), fuse.OK
}

// Unlink implements pathfs.Filesystem.
func (fs *FS) Unlink(path string, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}

	cName := filepath.Base(cPath)
	if nametransform.IsLongContent(cName) {
		var dirfd *os.File
		dirfd, err = os.Open(filepath.Dir(cPath))
		if err != nil {
			return fuse.ToStatus(err)
		}
		defer dirfd.Close()
		// Delete content
		err = syscallcompat.Unlinkat(int(dirfd.Fd()), cName)
		if err != nil {
			return fuse.ToStatus(err)
		}
		// Delete ".name"
		err = nametransform.DeleteLongName(dirfd, cName)
		if err != nil {
			tlog.Warn.Printf("Unlink: could not delete .name file: %v", err)
		}
		return fuse.ToStatus(err)
	}

	err = syscall.Unlink(cPath)
	return fuse.ToStatus(err)
}

// Symlink implements pathfs.Filesystem.
func (fs *FS) Symlink(target string, linkName string, context *fuse.Context) (code fuse.Status) {
	tlog.Debug.Printf("Symlink(\"%s\", \"%s\")", target, linkName)
	if fs.isFiltered(linkName) {
		return fuse.EPERM
	}
	cPath, err := fs.getBackingPath(linkName)
	if err != nil {
		return fuse.ToStatus(err)
	}
	if fs.args.PlaintextNames {
		err = os.Symlink(target, cPath)
		return fuse.ToStatus(err)
	}
	// Symlinks are encrypted like file contents (GCM) and base64-encoded
	cBinTarget := fs.contentEnc.EncryptBlock([]byte(target), 0, nil)
	cTarget := base64.URLEncoding.EncodeToString(cBinTarget)

	// Handle long file name
	cName := filepath.Base(cPath)
	if nametransform.IsLongContent(cName) {
		var dirfd *os.File
		dirfd, err = os.Open(filepath.Dir(cPath))
		if err != nil {
			return fuse.ToStatus(err)
		}
		defer dirfd.Close()

		// Create ".name"
		err = fs.nameTransform.WriteLongName(dirfd, cName, linkName)
		if err != nil {
			return fuse.ToStatus(err)
		}

		// Create symlink
		// TODO use syscall.Symlinkat once it is available in Go
		err = syscall.Symlink(cTarget, cPath)
		if err != nil {
			nametransform.DeleteLongName(dirfd, cName)
		}

		return fuse.ToStatus(err)
	}

	err = os.Symlink(cTarget, cPath)
	return fuse.ToStatus(err)
}

// Rename implements pathfs.Filesystem.
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

	// Handle long source file name
	var oldDirFd *os.File
	var finalOldDirFd int
	var finalOldPath = cOldPath
	cOldName := filepath.Base(cOldPath)
	if nametransform.IsLongContent(cOldName) {
		oldDirFd, err = os.Open(filepath.Dir(cOldPath))
		if err != nil {
			return fuse.ToStatus(err)
		}
		defer oldDirFd.Close()
		finalOldDirFd = int(oldDirFd.Fd())
		// Use relative path
		finalOldPath = cOldName
	}
	// Handle long destination file name
	var newDirFd *os.File
	var finalNewDirFd int
	var finalNewPath = cNewPath
	cNewName := filepath.Base(cNewPath)
	if nametransform.IsLongContent(cNewName) {
		newDirFd, err = os.Open(filepath.Dir(cNewPath))
		if err != nil {
			return fuse.ToStatus(err)
		}
		defer newDirFd.Close()
		finalNewDirFd = int(newDirFd.Fd())
		// Use relative path
		finalNewPath = cNewName
		// Create destination .name file
		err = fs.nameTransform.WriteLongName(newDirFd, cNewName, newPath)
		if err != nil {
			return fuse.ToStatus(err)
		}
	}
	// Actual rename
	tlog.Debug.Printf("Renameat oldfd=%d oldpath=%s newfd=%d newpath=%s\n", finalOldDirFd, finalOldPath, finalNewDirFd, finalNewPath)
	err = syscallcompat.Renameat(finalOldDirFd, finalOldPath, finalNewDirFd, finalNewPath)
	if err == syscall.ENOTEMPTY || err == syscall.EEXIST {
		// If an empty directory is overwritten we will always get an error as
		// the "empty" directory will still contain gocryptfs.diriv.
		// Interestingly, ext4 returns ENOTEMPTY while xfs returns EEXIST.
		// We handle that by trying to fs.Rmdir() the target directory and trying
		// again.
		tlog.Debug.Printf("Rename: Handling ENOTEMPTY")
		if fs.Rmdir(newPath, context) == fuse.OK {
			err = syscallcompat.Renameat(finalOldDirFd, finalOldPath, finalNewDirFd, finalNewPath)
		}
	}
	if err != nil {
		if newDirFd != nil {
			// Roll back .name creation
			nametransform.DeleteLongName(newDirFd, cNewName)
		}
		return fuse.ToStatus(err)
	}
	if oldDirFd != nil {
		nametransform.DeleteLongName(oldDirFd, cOldName)
	}
	return fuse.OK
}

// Link implements pathfs.Filesystem.
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

	// Handle long file name
	cNewName := filepath.Base(cNewPath)
	if nametransform.IsLongContent(cNewName) {
		dirfd, err := os.Open(filepath.Dir(cNewPath))
		if err != nil {
			return fuse.ToStatus(err)
		}
		defer dirfd.Close()
		err = fs.nameTransform.WriteLongName(dirfd, cNewName, newPath)
		if err != nil {
			return fuse.ToStatus(err)
		}
		// TODO Use syscall.Linkat once it is available in Go (it is not in Go
		// 1.6).
		err = syscall.Link(cOldPath, cNewPath)
		if err != nil {
			nametransform.DeleteLongName(dirfd, cNewName)
			return fuse.ToStatus(err)
		}
	}

	return fuse.ToStatus(os.Link(cOldPath, cNewPath))
}

// Access implements pathfs.Filesystem.
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

// GetXAttr implements pathfs.Filesystem.
func (fs *FS) GetXAttr(name string, attr string, context *fuse.Context) ([]byte, fuse.Status) {
	return nil, fuse.ENOSYS
}

// SetXAttr implements pathfs.Filesystem.
func (fs *FS) SetXAttr(name string, attr string, data []byte, flags int, context *fuse.Context) fuse.Status {
	return fuse.ENOSYS
}

// ListXAttr implements pathfs.Filesystem.
func (fs *FS) ListXAttr(name string, context *fuse.Context) ([]string, fuse.Status) {
	return nil, fuse.ENOSYS
}

// RemoveXAttr implements pathfs.Filesystem.
func (fs *FS) RemoveXAttr(name string, attr string, context *fuse.Context) fuse.Status {
	return fuse.ENOSYS
}
