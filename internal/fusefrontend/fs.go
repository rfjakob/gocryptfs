// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

// FUSE operations on paths

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/serialize_reads"
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
	// This lock is used by openWriteOnlyFile() to block concurrent opens while
	// it relaxes the permissions on a file.
	openWriteOnlyLock sync.RWMutex
	// MitigatedCorruptions is used to report data corruption that is internally
	// mitigated by ignoring the corrupt item. For example, when OpenDir() finds
	// a corrupt filename, we still return the other valid filenames.
	// The corruption is logged to syslog to inform the user,	and in addition,
	// the corrupt filename is logged to this channel via
	// reportMitigatedCorruption().
	// "gocryptfs -fsck" reads from the channel to also catch these transparently-
	// mitigated corruptions.
	MitigatedCorruptions chan string
	// Track accesses to the filesystem so that we can know when to autounmount.
	// An access is considered to have happened on every call to encryptPath,
	// which is called as part of every filesystem operation.
	// (This flag uses a uint32 so that it can be reset with CompareAndSwapUint32.)
	AccessedSinceLastCheck uint32
}

var _ pathfs.FileSystem = &FS{} // Verify that interface is implemented.

// NewFS returns a new encrypted FUSE overlay filesystem.
func NewFS(args Args, c *contentenc.ContentEnc, n *nametransform.NameTransform) *FS {
	if args.SerializeReads {
		serialize_reads.InitSerializer()
	}
	if len(args.Exclude) > 0 {
		tlog.Warn.Printf("Forward mode does not support -exclude")
	}
	return &FS{
		FileSystem:    pathfs.NewLoopbackFileSystem(args.Cipherdir),
		args:          args,
		nameTransform: n,
		contentEnc:    c,
	}
}

// GetAttr implements pathfs.Filesystem.
//
// GetAttr is symlink-safe through use of openBackingDir() and Fstatat().
func (fs *FS) GetAttr(relPath string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	tlog.Debug.Printf("FS.GetAttr(%q)", relPath)
	if fs.isFiltered(relPath) {
		return nil, fuse.EPERM
	}
	dirfd, cName, err := fs.openBackingDir(relPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	var st unix.Stat_t
	err = syscallcompat.Fstatat(dirfd, cName, &st, unix.AT_SYMLINK_NOFOLLOW)
	syscall.Close(dirfd)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	a := &fuse.Attr{}
	st2 := syscallcompat.Unix2syscall(st)
	a.FromStat(&st2)
	if a.IsRegular() {
		a.Size = fs.contentEnc.CipherSizeToPlainSize(a.Size)
	} else if a.IsSymlink() {
		target, _ := fs.Readlink(relPath, context)
		a.Size = uint64(len(target))
	}
	if fs.args.ForceOwner != nil {
		a.Owner = *fs.args.ForceOwner
	}
	return a, fuse.OK
}

// mangleOpenFlags is used by Create() and Open() to convert the open flags the user
// wants to the flags we internally use to open the backing file.
// The returned flags always contain O_NOFOLLOW.
func (fs *FS) mangleOpenFlags(flags uint32) (newFlags int) {
	newFlags = int(flags)
	// Convert WRONLY to RDWR. We always need read access to do read-modify-write cycles.
	if newFlags&os.O_WRONLY > 0 {
		newFlags = newFlags ^ os.O_WRONLY | os.O_RDWR
	}
	// We also cannot open the file in append mode, we need to seek back for RMW
	newFlags = newFlags &^ os.O_APPEND
	// O_DIRECT accesses must be aligned in both offset and length. Due to our
	// crypto header, alignment will be off, even if userspace makes aligned
	// accesses. Running xfstests generic/013 on ext4 used to trigger lots of
	// EINVAL errors due to missing alignment. Just fall back to buffered IO.
	newFlags = newFlags &^ syscallcompat.O_DIRECT
	// We always want O_NOFOLLOW to be safe against symlink races
	newFlags |= syscall.O_NOFOLLOW
	return newFlags
}

// Open - FUSE call. Open already-existing file.
//
// Symlink-safe through Openat().
func (fs *FS) Open(path string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	if fs.isFiltered(path) {
		return nil, fuse.EPERM
	}
	newFlags := fs.mangleOpenFlags(flags)
	// Taking this lock makes sure we don't race openWriteOnlyFile()
	fs.openWriteOnlyLock.RLock()
	defer fs.openWriteOnlyLock.RUnlock()
	// Symlink-safe open
	dirfd, cName, err := fs.openBackingDir(path)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	fd, err := syscallcompat.Openat(dirfd, cName, newFlags, 0)
	// Handle a few specific errors
	if err != nil {
		if err == syscall.EMFILE {
			var lim syscall.Rlimit
			syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
			tlog.Warn.Printf("Open %q: too many open files. Current \"ulimit -n\": %d", cName, lim.Cur)
		}
		if err == syscall.EACCES && (int(flags)&os.O_WRONLY > 0) {
			return fs.openWriteOnlyFile(dirfd, cName, newFlags)
		}
		return nil, fuse.ToStatus(err)
	}
	f := os.NewFile(uintptr(fd), cName)
	return NewFile(f, fs)
}

// Due to RMW, we always need read permissions on the backing file. This is a
// problem if the file permissions do not allow reading (i.e. 0200 permissions).
// This function works around that problem by chmod'ing the file, obtaining a fd,
// and chmod'ing it back.
func (fs *FS) openWriteOnlyFile(dirfd int, cName string, newFlags int) (fuseFile nodefs.File, status fuse.Status) {
	woFd, err := syscallcompat.Openat(dirfd, cName, syscall.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	defer syscall.Close(woFd)
	var st syscall.Stat_t
	err = syscall.Fstat(woFd, &st)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// The cast to uint32 fixes a build failure on Darwin, where st.Mode is uint16.
	perms := uint32(st.Mode & 0777)
	// Verify that we don't have read permissions
	if perms&0400 != 0 {
		tlog.Warn.Printf("openWriteOnlyFile: unexpected permissions %#o, returning EPERM", perms)
		return nil, fuse.ToStatus(syscall.EPERM)
	}
	// Upgrade the lock to block other Open()s and downgrade again on return
	fs.openWriteOnlyLock.RUnlock()
	fs.openWriteOnlyLock.Lock()
	defer func() {
		fs.openWriteOnlyLock.Unlock()
		fs.openWriteOnlyLock.RLock()
	}()
	// Relax permissions and revert on return
	syscall.Fchmod(woFd, perms|0400)
	if err != nil {
		tlog.Warn.Printf("openWriteOnlyFile: changing permissions failed: %v", err)
		return nil, fuse.ToStatus(err)
	}
	defer func() {
		err2 := syscall.Fchmod(woFd, perms)
		if err2 != nil {
			tlog.Warn.Printf("openWriteOnlyFile: reverting permissions failed: %v", err2)
		}
	}()
	rwFd, err := syscallcompat.Openat(dirfd, cName, newFlags, 0)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	f := os.NewFile(uintptr(rwFd), cName)
	return NewFile(f, fs)
}

// Create - FUSE call. Creates a new file.
//
// Symlink-safe through the use of Openat().
func (fs *FS) Create(path string, flags uint32, mode uint32, context *fuse.Context) (nodefs.File, fuse.Status) {
	if fs.isFiltered(path) {
		return nil, fuse.EPERM
	}
	newFlags := fs.mangleOpenFlags(flags)
	dirfd, cName, err := fs.openBackingDir(path)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	fd := -1
	// Handle long file name
	if !fs.args.PlaintextNames && nametransform.IsLongContent(cName) {
		// Create ".name"
		err = fs.nameTransform.WriteLongName(dirfd, cName, path)
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
		// Create content
		fd, err = syscallcompat.Openat(dirfd, cName, newFlags|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			nametransform.DeleteLongName(dirfd, cName)
			return nil, fuse.ToStatus(err)
		}

	} else {
		// Create content, normal (short) file name
		fd, err = syscallcompat.Openat(dirfd, cName, newFlags|syscall.O_CREAT|syscall.O_EXCL, mode)
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
	}
	// Set owner
	if fs.args.PreserveOwner {
		err = syscall.Fchown(fd, int(context.Owner.Uid), int(context.Owner.Gid))
		if err != nil {
			tlog.Warn.Printf("Create: Fchown() failed: %v", err)
		}
	}
	f := os.NewFile(uintptr(fd), cName)
	return NewFile(f, fs)
}

// Chmod - FUSE call. Change permissons on "path".
//
// Symlink-safe through use of Fchmodat().
func (fs *FS) Chmod(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	dirfd, cName, err := fs.openBackingDir(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	// os.Chmod goes through the "syscallMode" translation function that messes
	// up the suid and sgid bits. So use a syscall directly.
	err = syscallcompat.Fchmodat(dirfd, cName, mode, unix.AT_SYMLINK_NOFOLLOW)
	return fuse.ToStatus(err)
}

// Chown - FUSE call. Change the owner of "path".
//
// Symlink-safe through use of Fchownat().
func (fs *FS) Chown(path string, uid uint32, gid uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	dirfd, cName, err := fs.openBackingDir(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	code = fuse.ToStatus(syscallcompat.Fchownat(dirfd, cName, int(uid), int(gid), unix.AT_SYMLINK_NOFOLLOW))
	if !code.Ok() {
		return code
	}
	if !fs.args.PlaintextNames {
		// When filename encryption is active, every directory contains
		// a "gocryptfs.diriv" file. This file should also change the owner.
		// Instead of checking if "cName" is a directory, we just blindly
		// execute the chown on "cName/gocryptfs.diriv" and ignore errors.
		dirIVPath := filepath.Join(cName, nametransform.DirIVFilename)
		syscallcompat.Fchownat(dirfd, dirIVPath, int(uid), int(gid), unix.AT_SYMLINK_NOFOLLOW)
	}
	return fuse.OK
}

// Mknod - FUSE call. Create a device file.
//
// Symlink-safe through use of Mknodat().
func (fs *FS) Mknod(path string, mode uint32, dev uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	dirfd, cName, err := fs.openBackingDir(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	// Create ".name" file to store long file name (except in PlaintextNames mode)
	if !fs.args.PlaintextNames && nametransform.IsLongContent(cName) {
		err = fs.nameTransform.WriteLongName(dirfd, cName, path)
		if err != nil {
			return fuse.ToStatus(err)
		}
		// Create "gocryptfs.longfile." device node
		err = syscallcompat.Mknodat(dirfd, cName, mode, int(dev))
		if err != nil {
			nametransform.DeleteLongName(dirfd, cName)
		}
	} else {
		// Create regular device node
		err = syscallcompat.Mknodat(dirfd, cName, mode, int(dev))
	}
	if err != nil {
		return fuse.ToStatus(err)
	}
	// Set owner
	if fs.args.PreserveOwner {
		err = syscallcompat.Fchownat(dirfd, cName, int(context.Owner.Uid),
			int(context.Owner.Gid), unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			tlog.Warn.Printf("Mknod: Fchownat failed: %v", err)
		}
	}
	return fuse.OK
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

// Utimens - FUSE call. Set the timestamps on file "path".
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

// StatFs - FUSE call. Returns information about the filesystem.
//
// Symlink-safe because the passed path is ignored.
func (fs *FS) StatFs(path string) *fuse.StatfsOut {
	return fs.FileSystem.StatFs("")
}

// decryptSymlinkTarget: "cData64" is base64-decoded and decrypted
// like file contents (GCM).
// The empty string decrypts to the empty string.
func (fs *FS) decryptSymlinkTarget(cData64 string) (string, error) {
	if cData64 == "" {
		return "", nil
	}
	cData, err := fs.nameTransform.B64.DecodeString(cData64)
	if err != nil {
		return "", err
	}
	data, err := fs.contentEnc.DecryptBlock([]byte(cData), 0, nil)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Readlink implements pathfs.Filesystem.
func (fs *FS) Readlink(relPath string, context *fuse.Context) (out string, status fuse.Status) {
	cPath, err := fs.encryptPath(relPath)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	cAbsPath := filepath.Join(fs.args.Cipherdir, cPath)
	cTarget, err := os.Readlink(cAbsPath)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	if fs.args.PlaintextNames {
		return cTarget, fuse.OK
	}
	// Symlinks are encrypted like file contents (GCM) and base64-encoded
	target, err := fs.decryptSymlinkTarget(cTarget)
	if err != nil {
		tlog.Warn.Printf("Readlink %q: decrypting target failed: %v", cPath, err)
		return "", fuse.EIO
	}
	return string(target), fuse.OK
}

// Unlink implements pathfs.Filesystem.
func (fs *FS) Unlink(path string, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	dirfd, cName, err := fs.openBackingDir(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	// Delete content
	err = syscallcompat.Unlinkat(dirfd, cName, 0)
	if err != nil {
		return fuse.ToStatus(err)
	}
	// Delete ".name" file
	if !fs.args.PlaintextNames && nametransform.IsLongContent(cName) {
		err = nametransform.DeleteLongName(dirfd, cName)
		if err != nil {
			tlog.Warn.Printf("Unlink: could not delete .name file: %v", err)
		}
	}
	return fuse.ToStatus(err)
}

// encryptSymlinkTarget: "data" is encrypted like file contents (GCM)
// and base64-encoded.
// The empty string encrypts to the empty string.
func (fs *FS) encryptSymlinkTarget(data string) (cData64 string) {
	if data == "" {
		return ""
	}
	cData := fs.contentEnc.EncryptBlock([]byte(data), 0, nil)
	cData64 = fs.nameTransform.B64.EncodeToString(cData)
	return cData64
}

// Symlink implements pathfs.Filesystem.
func (fs *FS) Symlink(target string, linkName string, context *fuse.Context) (code fuse.Status) {
	tlog.Debug.Printf("Symlink(\"%s\", \"%s\")", target, linkName)
	if fs.isFiltered(linkName) {
		return fuse.EPERM
	}
	dirfd, cName, err := fs.openBackingDir(linkName)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	cTarget := target
	if !fs.args.PlaintextNames {
		// Symlinks are encrypted like file contents (GCM) and base64-encoded
		cTarget = fs.encryptSymlinkTarget(target)
	}
	// Create ".name" file to store long file name (except in PlaintextNames mode)
	if !fs.args.PlaintextNames && nametransform.IsLongContent(cName) {
		err = fs.nameTransform.WriteLongName(dirfd, cName, linkName)
		if err != nil {
			return fuse.ToStatus(err)
		}
		// Create "gocryptfs.longfile." symlink
		err = syscallcompat.Symlinkat(cTarget, dirfd, cName)
		if err != nil {
			nametransform.DeleteLongName(dirfd, cName)
		}
	} else {
		// Create symlink
		err = syscallcompat.Symlinkat(cTarget, dirfd, cName)
	}
	if err != nil {
		return fuse.ToStatus(err)
	}
	// Set owner
	if fs.args.PreserveOwner {
		err = syscallcompat.Fchownat(dirfd, cName, int(context.Owner.Uid),
			int(context.Owner.Gid), unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			tlog.Warn.Printf("Symlink: Fchownat failed: %v", err)
		}
	}
	return fuse.OK
}

// Rename implements pathfs.Filesystem.
func (fs *FS) Rename(oldPath string, newPath string, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(newPath) {
		return fuse.EPERM
	}
	oldDirfd, oldCName, err := fs.openBackingDir(oldPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(oldDirfd)
	newDirfd, newCName, err := fs.openBackingDir(newPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(newDirfd)
	// The Rename may cause a directory to take the place of another directory.
	// That directory may still be in the DirIV cache, clear it.
	fs.nameTransform.DirIVCache.Clear()
	// Easy case.
	if fs.args.PlaintextNames {
		return fuse.ToStatus(syscallcompat.Renameat(oldDirfd, oldCName, newDirfd, newCName))
	}
	// Long destination file name: create .name file
	nameFileAlreadyThere := false
	if nametransform.IsLongContent(newCName) {
		err = fs.nameTransform.WriteLongName(newDirfd, newCName, newPath)
		// Failure to write the .name file is expected when the target path already
		// exists. Since hashes are pretty unique, there is no need to modify the
		// .name file in this case, and we ignore the error.
		if err == syscall.EEXIST {
			nameFileAlreadyThere = true
		} else if err != nil {
			return fuse.ToStatus(err)
		}
	}
	// Actual rename
	tlog.Debug.Printf("Renameat %d/%s -> %d/%s\n", oldDirfd, oldCName, newDirfd, newCName)
	err = syscallcompat.Renameat(oldDirfd, oldCName, newDirfd, newCName)
	if err == syscall.ENOTEMPTY || err == syscall.EEXIST {
		// If an empty directory is overwritten we will always get an error as
		// the "empty" directory will still contain gocryptfs.diriv.
		// Interestingly, ext4 returns ENOTEMPTY while xfs returns EEXIST.
		// We handle that by trying to fs.Rmdir() the target directory and trying
		// again.
		tlog.Debug.Printf("Rename: Handling ENOTEMPTY")
		if fs.Rmdir(newPath, context) == fuse.OK {
			err = syscallcompat.Renameat(oldDirfd, oldCName, newDirfd, newCName)
		}
	}
	if err != nil {
		if nametransform.IsLongContent(newCName) && nameFileAlreadyThere == false {
			// Roll back .name creation unless the .name file was already there
			nametransform.DeleteLongName(newDirfd, newCName)
		}
		return fuse.ToStatus(err)
	}
	if nametransform.IsLongContent(oldCName) {
		nametransform.DeleteLongName(oldDirfd, oldCName)
	}
	return fuse.OK
}

// Link - FUSE call. Creates a hard link at "newPath" pointing to file
// "oldPath".
//
// Symlink-safe through use of Linkat().
func (fs *FS) Link(oldPath string, newPath string, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(newPath) {
		return fuse.EPERM
	}
	oldDirFd, cOldName, err := fs.openBackingDir(oldPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(oldDirFd)
	newDirFd, cNewName, err := fs.openBackingDir(newPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(newDirFd)
	// Handle long file name (except in PlaintextNames mode)
	if !fs.args.PlaintextNames && nametransform.IsLongContent(cNewName) {
		err = fs.nameTransform.WriteLongName(newDirFd, cNewName, newPath)
		if err != nil {
			return fuse.ToStatus(err)
		}
		// Create "gocryptfs.longfile." link
		err = syscallcompat.Linkat(oldDirFd, cOldName, newDirFd, cNewName, 0)
		if err != nil {
			nametransform.DeleteLongName(newDirFd, cNewName)
		}
	} else {
		// Create regular link
		err = syscallcompat.Linkat(oldDirFd, cOldName, newDirFd, cNewName, 0)
	}
	return fuse.ToStatus(err)
}

// Access - FUSE call. Check if a file can be accessed in the specified mode(s)
// (read, write, execute).
//
// Symlink-safe through use of faccessat.
func (fs *FS) Access(relPath string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(relPath) {
		return fuse.EPERM
	}
	dirfd, cName, err := fs.openBackingDir(relPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	err = unix.Faccessat(dirfd, cName, mode, unix.AT_SYMLINK_NOFOLLOW)
	return fuse.ToStatus(err)
}

// reportMitigatedCorruption is used to report a corruption that was transparently
// mitigated and did not return an error to the user. Pass the name of the corrupt
// item (filename for OpenDir(), xattr name for ListXAttr() etc).
// See the MitigatedCorruptions channel for more info.
func (fs *FS) reportMitigatedCorruption(item string) {
	if fs.MitigatedCorruptions == nil {
		return
	}
	select {
	case fs.MitigatedCorruptions <- item:
	case <-time.After(1 * time.Second):
		tlog.Warn.Printf("BUG: reportCorruptItem: timeout")
		//debug.PrintStack()
		return
	}
}
