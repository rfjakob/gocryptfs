package fusefrontend

// Mkdir and Rmdir

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const dsStoreName = ".DS_Store"

// mkdirWithIv - create a new directory and corresponding diriv file. dirfd
// should be a handle to the parent directory, cName is the name of the new
// directory and mode specifies the access permissions to use.
func (fs *FS) mkdirWithIv(dirfd *os.File, cName string, mode uint32) error {
	// Between the creation of the directory and the creation of gocryptfs.diriv
	// the directory is inconsistent. Take the lock to prevent other readers
	// from seeing it.
	fs.dirIVLock.Lock()
	// The new directory may take the place of an older one that is still in the cache
	fs.nameTransform.DirIVCache.Clear()
	defer fs.dirIVLock.Unlock()
	err := syscallcompat.Mkdirat(int(dirfd.Fd()), cName, mode)
	if err != nil {
		return err
	}
	// Create gocryptfs.diriv
	err = nametransform.WriteDirIV(dirfd, cName)
	if err != nil {
		err2 := syscallcompat.Unlinkat(int(dirfd.Fd()), cName, unix.AT_REMOVEDIR)
		if err2 != nil {
			tlog.Warn.Printf("mkdirWithIv: rollback failed: %v", err2)
		}
	}
	return err
}

// Mkdir implements pathfs.FileSystem
func (fs *FS) Mkdir(newPath string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(newPath) {
		return fuse.EPERM
	}
	dirfd, cName, err := fs.openBackingPath(newPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer dirfd.Close()
	if fs.args.PlaintextNames {
		err = syscallcompat.Mkdirat(int(dirfd.Fd()), cName, mode)
		// Set owner
		if fs.args.PreserveOwner {
			err = syscallcompat.Fchownat(int(dirfd.Fd()), cName, int(context.Owner.Uid),
				int(context.Owner.Gid), unix.AT_SYMLINK_NOFOLLOW)
			if err != nil {
				tlog.Warn.Printf("Mkdir: Fchownat failed: %v", err)
			}
		}
		return fuse.ToStatus(err)
	}

	// We need write and execute permissions to create gocryptfs.diriv
	origMode := mode
	mode = mode | 0300

	// Handle long file name
	if nametransform.IsLongContent(cName) {
		// Create ".name"
		err = fs.nameTransform.WriteLongName(dirfd, cName, newPath)
		if err != nil {
			return fuse.ToStatus(err)
		}

		// Create directory
		err = fs.mkdirWithIv(dirfd, cName, mode)
		if err != nil {
			nametransform.DeleteLongName(dirfd, cName)
			return fuse.ToStatus(err)
		}
	} else {
		err = fs.mkdirWithIv(dirfd, cName, mode)
		if err != nil {
			return fuse.ToStatus(err)
		}
	}
	// Set permissions back to what the user wanted
	if origMode != mode {
		err = syscallcompat.Fchmodat(int(dirfd.Fd()), cName, origMode, unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			tlog.Warn.Printf("Mkdir: Fchmodat failed: %v", err)
		}
	}
	// Set owner
	if fs.args.PreserveOwner {
		err = syscallcompat.Fchownat(int(dirfd.Fd()), cName, int(context.Owner.Uid),
			int(context.Owner.Gid), unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			tlog.Warn.Printf("Mkdir: Fchownat 1 failed: %v", err)
		}
		err = syscallcompat.Fchownat(int(dirfd.Fd()), filepath.Join(cName, nametransform.DirIVFilename),
			int(context.Owner.Uid), int(context.Owner.Gid), unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			tlog.Warn.Printf("Mkdir: Fchownat 2 failed: %v", err)
		}
	}
	return fuse.OK
}

// haveDsstore return true if one of the entries in "names" is ".DS_Store".
func haveDsstore(names []string) bool {
	for _, n := range names {
		if n == dsStoreName {
			return true
		}
	}
	return false
}

// Rmdir implements pathfs.FileSystem
func (fs *FS) Rmdir(path string, context *fuse.Context) (code fuse.Status) {
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return fuse.ToStatus(err)
	}
	if fs.args.PlaintextNames {
		err = syscall.Rmdir(cPath)
		return fuse.ToStatus(err)
	}
	parentDir := filepath.Dir(cPath)
	parentDirFd, err := os.Open(parentDir)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer parentDirFd.Close()

	cName := filepath.Base(cPath)
	dirfdRaw, err := syscallcompat.Openat(int(parentDirFd.Fd()), cName,
		syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err == syscall.EACCES {
		// We need permission to read and modify the directory
		tlog.Debug.Printf("Rmdir: handling EACCESS")
		// TODO use syscall.Fstatat once it is available in Go
		var fi os.FileInfo
		fi, err = os.Lstat(cPath)
		if err != nil {
			tlog.Debug.Printf("Rmdir: Stat: %v", err)
			return fuse.ToStatus(err)
		}
		origMode := fi.Mode()
		// TODO use syscall.Chmodat once it is available in Go
		err = os.Chmod(cPath, origMode|0700)
		if err != nil {
			tlog.Debug.Printf("Rmdir: Chmod failed: %v", err)
			return fuse.ToStatus(err)
		}
		// Retry open
		var st syscall.Stat_t
		syscall.Lstat(cPath, &st)
		dirfdRaw, err = syscallcompat.Openat(int(parentDirFd.Fd()), cName,
			syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
		// Undo the chmod if removing the directory failed
		defer func() {
			if code != fuse.OK {
				err = os.Chmod(cPath, origMode)
				if err != nil {
					tlog.Warn.Printf("Rmdir: Chmod rollback failed: %v", err)
				}
			}
		}()
	}
	if err != nil {
		tlog.Debug.Printf("Rmdir: Open: %v", err)
		return fuse.ToStatus(err)
	}
	dirfd := os.NewFile(uintptr(dirfdRaw), cName)
	defer dirfd.Close()
retry:
	// Check directory contents
	children, err := dirfd.Readdirnames(10)
	if err == io.EOF {
		// The directory is empty
		tlog.Warn.Printf("Rmdir: %q: gocryptfs.diriv is missing", cPath)
		return fuse.ToStatus(syscall.Rmdir(cPath))
	}
	if err != nil {
		tlog.Warn.Printf("Rmdir: Readdirnames: %v", err)
		return fuse.ToStatus(err)
	}
	// MacOS sprinkles .DS_Store files everywhere. This is hard to avoid for
	// users, so handle it transparently here.
	if runtime.GOOS == "darwin" && len(children) <= 2 && haveDsstore(children) {
		ds := filepath.Join(cPath, dsStoreName)
		err = syscall.Unlink(ds)
		if err != nil {
			tlog.Warn.Printf("Rmdir: failed to delete blocking file %q: %v", ds, err)
			return fuse.ToStatus(err)
		}
		tlog.Warn.Printf("Rmdir: had to delete blocking file %q", ds)
		goto retry
	}
	// If the directory is not empty besides gocryptfs.diriv, do not even
	// attempt the dance around gocryptfs.diriv.
	if len(children) > 1 {
		return fuse.ToStatus(syscall.ENOTEMPTY)
	}
	// Move "gocryptfs.diriv" to the parent dir as "gocryptfs.diriv.rmdir.XYZ"
	tmpName := fmt.Sprintf("gocryptfs.diriv.rmdir.%d", cryptocore.RandUint64())
	tlog.Debug.Printf("Rmdir: Renaming %s to %s", nametransform.DirIVFilename, tmpName)
	// The directory is in an inconsistent state between rename and rmdir.
	// Protect against concurrent readers.
	fs.dirIVLock.Lock()
	defer fs.dirIVLock.Unlock()
	err = syscallcompat.Renameat(int(dirfd.Fd()), nametransform.DirIVFilename,
		int(parentDirFd.Fd()), tmpName)
	if err != nil {
		tlog.Warn.Printf("Rmdir: Renaming %s to %s failed: %v",
			nametransform.DirIVFilename, tmpName, err)
		return fuse.ToStatus(err)
	}
	// Actual Rmdir
	err = syscallcompat.Unlinkat(int(parentDirFd.Fd()), cName, unix.AT_REMOVEDIR)
	if err != nil {
		// This can happen if another file in the directory was created in the
		// meantime, undo the rename
		err2 := syscallcompat.Renameat(int(parentDirFd.Fd()), tmpName,
			int(dirfd.Fd()), nametransform.DirIVFilename)
		if err != nil {
			tlog.Warn.Printf("Rmdir: Rename rollback failed: %v", err2)
		}
		return fuse.ToStatus(err)
	}
	// Delete "gocryptfs.diriv.rmdir.XYZ"
	err = syscallcompat.Unlinkat(int(parentDirFd.Fd()), tmpName, 0)
	if err != nil {
		tlog.Warn.Printf("Rmdir: Could not clean up %s: %v", tmpName, err)
	}
	// Delete .name file
	if nametransform.IsLongContent(cName) {
		nametransform.DeleteLongName(parentDirFd, cName)
	}
	// The now-deleted directory may have been in the DirIV cache. Clear it.
	fs.nameTransform.DirIVCache.Clear()
	return fuse.OK
}

// OpenDir implements pathfs.FileSystem
func (fs *FS) OpenDir(dirName string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	tlog.Debug.Printf("OpenDir(%s)", dirName)
	cDirName, err := fs.encryptPath(dirName)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Read ciphertext directory
	cDirAbsPath := filepath.Join(fs.args.Cipherdir, cDirName)
	var cipherEntries []fuse.DirEntry
	var status fuse.Status
	fd, err := syscall.Open(cDirAbsPath, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	defer syscall.Close(fd)
	cipherEntries, err = syscallcompat.Getdents(fd)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Get DirIV (stays nil if PlaintextNames is used)
	var cachedIV []byte
	if !fs.args.PlaintextNames {
		cachedIV, _ = fs.nameTransform.DirIVCache.Lookup(dirName)
		if cachedIV == nil {
			// Read the DirIV from disk and store it in the cache
			fs.dirIVLock.RLock()
			cachedIV, err = nametransform.ReadDirIV(cDirAbsPath)
			if err != nil {
				fs.dirIVLock.RUnlock()
				// The directory itself does not exist
				if err == syscall.ENOENT {
					return nil, fuse.ENOENT
				}
				// Any other problem warrants an error message
				tlog.Warn.Printf("OpenDir %q: could not read gocryptfs.diriv: %v", cDirName, err)
				return nil, fuse.EIO
			}
			fs.nameTransform.DirIVCache.Store(dirName, cachedIV, cDirName)
			fs.dirIVLock.RUnlock()
		}
	}
	// Decrypted directory entries
	var plain []fuse.DirEntry
	var errorCount int
	// Filter and decrypt filenames
	for i := range cipherEntries {
		cName := cipherEntries[i].Name
		if dirName == "" && cName == configfile.ConfDefaultName {
			// silently ignore "gocryptfs.conf" in the top level dir
			continue
		}
		if fs.args.PlaintextNames {
			plain = append(plain, cipherEntries[i])
			continue
		}
		if cName == nametransform.DirIVFilename {
			// silently ignore "gocryptfs.diriv" everywhere if dirIV is enabled
			continue
		}
		// Handle long file name
		isLong := nametransform.LongNameNone
		if fs.args.LongNames {
			isLong = nametransform.NameType(cName)
		}
		if isLong == nametransform.LongNameContent {
			cNameLong, err := nametransform.ReadLongName(filepath.Join(cDirAbsPath, cName))
			if err != nil {
				tlog.Warn.Printf("OpenDir %q: invalid entry %q: Could not read .name: %v",
					cDirName, cName, err)
				fs.reportMitigatedCorruption(cName)
				errorCount++
				continue
			}
			cName = cNameLong
		} else if isLong == nametransform.LongNameFilename {
			// ignore "gocryptfs.longname.*.name"
			continue
		}
		name, err := fs.nameTransform.DecryptName(cName, cachedIV)
		if err != nil {
			tlog.Warn.Printf("OpenDir %q: invalid entry %q: %v",
				cDirName, cName, err)
			fs.reportMitigatedCorruption(cName)
			if runtime.GOOS == "darwin" && cName == dsStoreName {
				// MacOS creates lots of these files. Log the warning but don't
				// increment errorCount - does not warrant returning EIO.
				continue
			}
			errorCount++
			continue
		}
		// Override the ciphertext name with the plaintext name but reuse the rest
		// of the structure
		cipherEntries[i].Name = name
		plain = append(plain, cipherEntries[i])
	}

	if errorCount > 0 && len(plain) == 0 {
		// Don't let the user stare on an empty directory. Report that things went
		// wrong.
		tlog.Warn.Printf("OpenDir %q: all %d entries were invalid, returning EIO",
			cDirName, errorCount)
		status = fuse.EIO
	}

	return plain, status
}
