// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

// FUSE operations on paths

import (
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/serialize_reads"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// FS implements the go-fuse virtual filesystem interface.
type FS struct {
	// Embed pathfs.defaultFileSystem to avoid compile failure when the
	// pathfs.FileSystem interface gets new functions. defaultFileSystem
	// provides a no-op implementation for all functions.
	pathfs.FileSystem
	args Args // Stores configuration arguments
	// dirIVLock: Lock()ed if any "gocryptfs.diriv" file is modified
	// Readers must RLock() it to prevent them from seeing intermediate
	// states
	dirIVLock sync.RWMutex
	// Filename encryption helper
	nameTransform nametransform.NameTransformer
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

	dirCache dirCacheStruct
}

//var _ pathfs.FileSystem = &FS{} // Verify that interface is implemented.

// NewFS returns a new encrypted FUSE overlay filesystem.
func NewFS(args Args, c *contentenc.ContentEnc, n nametransform.NameTransformer) *FS {
	if args.SerializeReads {
		serialize_reads.InitSerializer()
	}
	if len(args.Exclude) > 0 {
		tlog.Warn.Printf("Forward mode does not support -exclude")
	}
	return &FS{
		FileSystem:    pathfs.NewDefaultFileSystem(),
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
	if (newFlags & syscall.O_ACCMODE) == syscall.O_WRONLY {
		newFlags = newFlags ^ os.O_WRONLY | os.O_RDWR
	}
	// We also cannot open the file in append mode, we need to seek back for RMW
	newFlags = newFlags &^ os.O_APPEND
	// O_DIRECT accesses must be aligned in both offset and length. Due to our
	// crypto header, alignment will be off, even if userspace makes aligned
	// accesses. Running xfstests generic/013 on ext4 used to trigger lots of
	// EINVAL errors due to missing alignment. Just fall back to buffered IO.
	newFlags = newFlags &^ syscallcompat.O_DIRECT
	// Create and Open are two separate FUSE operations, so O_CREAT should not
	// be part of the open flags.
	newFlags = newFlags &^ syscall.O_CREAT
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
		if err == syscall.EACCES && (int(flags)&syscall.O_ACCMODE) == syscall.O_WRONLY {
			return fs.openWriteOnlyFile(dirfd, cName, newFlags)
		}
		return nil, fuse.ToStatus(err)
	}
	f := os.NewFile(uintptr(fd), cName)
	return NewFile(f, fs)
}

// openBackingFile opens the ciphertext file that backs relative plaintext
// path "relPath". Always adds O_NOFOLLOW to the flags.
func (fs *FS) openBackingFile(relPath string, flags int) (fd int, err error) {
	dirfd, cName, err := fs.openBackingDir(relPath)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(dirfd)
	return syscallcompat.Openat(dirfd, cName, flags|syscall.O_NOFOLLOW, 0)
}

// Due to RMW, we always need read permissions on the backing file. This is a
// problem if the file permissions do not allow reading (i.e. 0200 permissions).
// This function works around that problem by chmod'ing the file, obtaining a fd,
// and chmod'ing it back.
func (fs *FS) openWriteOnlyFile(dirfd int, cName string, newFlags int) (*File, fuse.Status) {
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
	perms := uint32(st.Mode)
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
	err = syscall.Fchmod(woFd, perms|0400)
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
	// Make sure context is nil if we don't want to preserve the owner
	if !fs.args.PreserveOwner {
		context = nil
	}
	// Handle long file name
	if !fs.args.PlaintextNames && nametransform.IsLongContent(cName) {
		// Create ".name"
		err = fs.nameTransform.WriteLongNameAt(dirfd, cName, path)
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
		// Create content
		fd, err = syscallcompat.OpenatUser(dirfd, cName, newFlags|syscall.O_CREAT|syscall.O_EXCL, mode, context)
		if err != nil {
			nametransform.DeleteLongNameAt(dirfd, cName)
		}
	} else {
		// Create content, normal (short) file name
		fd, err = syscallcompat.OpenatUser(dirfd, cName, newFlags|syscall.O_CREAT|syscall.O_EXCL, mode, context)
	}
	if err != nil {
		// xfstests generic/488 triggers this
		if err == syscall.EMFILE {
			var lim syscall.Rlimit
			syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
			tlog.Warn.Printf("Create %q: too many open files. Current \"ulimit -n\": %d", cName, lim.Cur)
		}
		return nil, fuse.ToStatus(err)
	}
	f := os.NewFile(uintptr(fd), cName)
	return NewFile(f, fs)
}

// Chmod - FUSE call. Change permissions on "path".
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
	err = syscallcompat.FchmodatNofollow(dirfd, cName, mode)
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
	err = syscallcompat.Fchownat(dirfd, cName, int(uid), int(gid), unix.AT_SYMLINK_NOFOLLOW)
	return fuse.ToStatus(err)
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
	// Make sure context is nil if we don't want to preserve the owner
	if !fs.args.PreserveOwner {
		context = nil
	}
	// Create ".name" file to store long file name (except in PlaintextNames mode)
	if !fs.args.PlaintextNames && nametransform.IsLongContent(cName) {
		err = fs.nameTransform.WriteLongNameAt(dirfd, cName, path)
		if err != nil {
			return fuse.ToStatus(err)
		}
		// Create "gocryptfs.longfile." device node
		err = syscallcompat.MknodatUser(dirfd, cName, mode, int(dev), context)
		if err != nil {
			nametransform.DeleteLongNameAt(dirfd, cName)
		}
	} else {
		// Create regular device node
		err = syscallcompat.MknodatUser(dirfd, cName, mode, int(dev), context)
	}
	return fuse.ToStatus(err)
}

// Truncate - FUSE call. Truncates a file.
//
// Support truncate(2) by opening the file and calling ftruncate(2)
// While the glibc "truncate" wrapper seems to always use ftruncate, fsstress from
// xfstests uses this a lot by calling "truncate64" directly.
//
// Symlink-safe by letting file.Truncate() do all the work.
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
//
// Symlink-safe through UtimesNanoAt.
func (fs *FS) Utimens(path string, a *time.Time, m *time.Time, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(path) {
		return fuse.EPERM
	}
	dirfd, cName, err := fs.openBackingDir(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	err = syscallcompat.UtimesNanoAtNofollow(dirfd, cName, a, m)
	return fuse.ToStatus(err)
}

// StatFs - FUSE call. Returns information about the filesystem.
//
// Symlink-safe because the passed path is ignored.
func (fs *FS) StatFs(path string) *fuse.StatfsOut {
	var st syscall.Statfs_t
	err := syscall.Statfs(fs.args.Cipherdir, &st)
	if err == nil {
		var out fuse.StatfsOut
		out.FromStatfsT(&st)
		return &out
	}
	return nil
}

// decryptSymlinkTarget: "cData64" is base64-decoded and decrypted
// like file contents (GCM).
// The empty string decrypts to the empty string.
//
// This function does not do any I/O and is hence symlink-safe.
func (fs *FS) decryptSymlinkTarget(cData64 string) (string, error) {
	if cData64 == "" {
		return "", nil
	}
	cData, err := fs.nameTransform.B64DecodeString(cData64)
	if err != nil {
		return "", err
	}
	data, err := fs.contentEnc.DecryptBlock([]byte(cData), 0, nil)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Readlink - FUSE call.
//
// Symlink-safe through openBackingDir() + Readlinkat().
func (fs *FS) Readlink(relPath string, context *fuse.Context) (out string, status fuse.Status) {
	dirfd, cName, err := fs.openBackingDir(relPath)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	cTarget, err := syscallcompat.Readlinkat(dirfd, cName)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	if fs.args.PlaintextNames {
		return cTarget, fuse.OK
	}
	// Symlinks are encrypted like file contents (GCM) and base64-encoded
	target, err := fs.decryptSymlinkTarget(cTarget)
	if err != nil {
		tlog.Warn.Printf("Readlink %q: decrypting target failed: %v", cName, err)
		return "", fuse.EIO
	}
	return string(target), fuse.OK
}

// Unlink - FUSE call. Delete a file.
//
// Symlink-safe through use of Unlinkat().
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
		err = nametransform.DeleteLongNameAt(dirfd, cName)
		if err != nil {
			tlog.Warn.Printf("Unlink: could not delete .name file: %v", err)
		}
	}
	return fuse.ToStatus(err)
}

// encryptSymlinkTarget: "data" is encrypted like file contents (GCM)
// and base64-encoded.
// The empty string encrypts to the empty string.
//
// Symlink-safe because it does not do any I/O.
func (fs *FS) encryptSymlinkTarget(data string) (cData64 string) {
	if data == "" {
		return ""
	}
	cData := fs.contentEnc.EncryptBlock([]byte(data), 0, nil)
	cData64 = fs.nameTransform.B64EncodeToString(cData)
	return cData64
}

// Symlink - FUSE call. Create a symlink.
//
// Symlink-safe through use of Symlinkat.
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
	// Make sure context is nil if we don't want to preserve the owner
	if !fs.args.PreserveOwner {
		context = nil
	}
	cTarget := target
	if !fs.args.PlaintextNames {
		// Symlinks are encrypted like file contents (GCM) and base64-encoded
		cTarget = fs.encryptSymlinkTarget(target)
	}
	// Create ".name" file to store long file name (except in PlaintextNames mode)
	if !fs.args.PlaintextNames && nametransform.IsLongContent(cName) {
		err = fs.nameTransform.WriteLongNameAt(dirfd, cName, linkName)
		if err != nil {
			return fuse.ToStatus(err)
		}
		// Create "gocryptfs.longfile." symlink
		err = syscallcompat.SymlinkatUser(cTarget, dirfd, cName, context)
		if err != nil {
			nametransform.DeleteLongNameAt(dirfd, cName)
		}
	} else {
		// Create symlink
		err = syscallcompat.SymlinkatUser(cTarget, dirfd, cName, context)
	}
	return fuse.ToStatus(err)
}

// Rename - FUSE call.
//
// Symlink-safe through Renameat().
func (fs *FS) Rename(oldPath string, newPath string, context *fuse.Context) (code fuse.Status) {
	defer fs.dirCache.Clear()
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
	// Easy case.
	if fs.args.PlaintextNames {
		return fuse.ToStatus(syscallcompat.Renameat(oldDirfd, oldCName, newDirfd, newCName))
	}
	// Long destination file name: create .name file
	nameFileAlreadyThere := false
	if nametransform.IsLongContent(newCName) {
		err = fs.nameTransform.WriteLongNameAt(newDirfd, newCName, newPath)
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
			nametransform.DeleteLongNameAt(newDirfd, newCName)
		}
		return fuse.ToStatus(err)
	}
	if nametransform.IsLongContent(oldCName) {
		nametransform.DeleteLongNameAt(oldDirfd, oldCName)
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
		err = fs.nameTransform.WriteLongNameAt(newDirFd, cNewName, newPath)
		if err != nil {
			return fuse.ToStatus(err)
		}
		// Create "gocryptfs.longfile." link
		err = syscallcompat.Linkat(oldDirFd, cOldName, newDirFd, cNewName, 0)
		if err != nil {
			nametransform.DeleteLongNameAt(newDirFd, cNewName)
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
// From https://github.com/libfuse/libfuse/blob/master/include/fuse.h :
//
// > Check file access permissions
// >
// > If the 'default_permissions' mount option is given, this method is not
// > called.
//
// We always enable default_permissions when -allow_other is passed, so there
// is no need for this function to check the uid in fuse.Context.
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
	err = syscallcompat.Faccessat(dirfd, cName, mode)
	syscall.Close(dirfd)
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

// isFiltered - check if plaintext "path" should be forbidden
//
// Prevents name clashes with internal files when file names are not encrypted
func (fs *FS) isFiltered(path string) bool {
	if !fs.args.PlaintextNames {
		return false
	}
	// gocryptfs.conf in the root directory is forbidden
	if path == configfile.ConfDefaultName {
		tlog.Info.Printf("The name /%s is reserved when -plaintextnames is used\n",
			configfile.ConfDefaultName)
		return true
	}
	// Note: gocryptfs.diriv is NOT forbidden because diriv and plaintextnames
	// are exclusive
	return false
}
