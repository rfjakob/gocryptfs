package fusefrontend

// Mkdir and Rmdir

import (
	"fmt"
	"io"
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
func (fs *FS) mkdirWithIv(dirfd int, cName string, mode uint32, context *fuse.Context) error {
	// Between the creation of the directory and the creation of gocryptfs.diriv
	// the directory is inconsistent. Take the lock to prevent other readers
	// from seeing it.
	fs.dirIVLock.Lock()
	defer fs.dirIVLock.Unlock()
	err := syscallcompat.MkdiratUser(dirfd, cName, mode, context)
	if err != nil {
		return err
	}
	dirfd2, err := syscallcompat.Openat(dirfd, cName, syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscallcompat.O_PATH, 0)
	if err == nil {
		// Create gocryptfs.diriv
		err = nametransform.WriteDirIVAt(dirfd2)
		syscall.Close(dirfd2)
	}
	if err != nil {
		// Delete inconsistent directory (missing gocryptfs.diriv!)
		err2 := syscallcompat.Unlinkat(dirfd, cName, unix.AT_REMOVEDIR)
		if err2 != nil {
			tlog.Warn.Printf("mkdirWithIv: rollback failed: %v", err2)
		}
	}
	return err
}

// Mkdir - FUSE call. Create a directory at "newPath" with permissions "mode".
//
// Symlink-safe through use of Mkdirat().
func (fs *FS) Mkdir(newPath string, mode uint32, context *fuse.Context) (code fuse.Status) {
	defer fs.dirCache.Clear()
	if fs.isFiltered(newPath) {
		return fuse.EPERM
	}
	dirfd, cName, err := fs.openBackingDir(newPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	// Make sure context is nil if we don't want to preserve the owner
	if !fs.args.PreserveOwner {
		context = nil
	}
	if fs.args.PlaintextNames {
		err = syscallcompat.MkdiratUser(dirfd, cName, mode, context)
		return fuse.ToStatus(err)
	}

	// We need write and execute permissions to create gocryptfs.diriv.
	// Also, we need read permissions to open the directory (to avoid
	// race-conditions between getting and setting the mode).
	origMode := mode
	mode = mode | 0700

	// Handle long file name
	if nametransform.IsLongContent(cName) {
		// Create ".name"
		err = fs.nameTransform.WriteLongNameAt(dirfd, cName, newPath)
		if err != nil {
			return fuse.ToStatus(err)
		}

		// Create directory
		err = fs.mkdirWithIv(dirfd, cName, mode, context)
		if err != nil {
			nametransform.DeleteLongNameAt(dirfd, cName)
			return fuse.ToStatus(err)
		}
	} else {
		err = fs.mkdirWithIv(dirfd, cName, mode, context)
		if err != nil {
			return fuse.ToStatus(err)
		}
	}
	// Set mode
	if origMode != mode {
		dirfd2, err := syscallcompat.Openat(dirfd, cName,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			tlog.Warn.Printf("Mkdir %q: Openat failed: %v", cName, err)
			return fuse.ToStatus(err)
		}
		defer syscall.Close(dirfd2)

		var st syscall.Stat_t
		err = syscall.Fstat(dirfd2, &st)
		if err != nil {
			tlog.Warn.Printf("Mkdir %q: Fstat failed: %v", cName, err)
			return fuse.ToStatus(err)
		}

		// Preserve SGID bit if it was set due to inheritance.
		origMode = uint32(st.Mode&^0777) | origMode
		err = syscall.Fchmod(dirfd2, origMode)
		if err != nil {
			tlog.Warn.Printf("Mkdir %q: Fchmod %#o -> %#o failed: %v", cName, mode, origMode, err)
			return fuse.ToStatus(err)
		}
	}
	return fuse.OK
}

// haveDsstore return true if one of the entries in "names" is ".DS_Store".
func haveDsstore(entries []fuse.DirEntry) bool {
	for _, e := range entries {
		if e.Name == dsStoreName {
			return true
		}
	}
	return false
}

// Rmdir - FUSE call.
//
// Symlink-safe through Unlinkat() + AT_REMOVEDIR.
func (fs *FS) Rmdir(relPath string, context *fuse.Context) (code fuse.Status) {
	defer fs.dirCache.Clear()
	parentDirFd, cName, err := fs.openBackingDir(relPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(parentDirFd)
	if fs.args.PlaintextNames {
		// Unlinkat with AT_REMOVEDIR is equivalent to Rmdir
		err = unix.Unlinkat(parentDirFd, cName, unix.AT_REMOVEDIR)
		return fuse.ToStatus(err)
	}
	// Unless we are running as root, we need read, write and execute permissions
	// to handle gocryptfs.diriv.
	permWorkaround := false
	var origMode uint32
	if !fs.args.PreserveOwner {
		var st unix.Stat_t
		err = syscallcompat.Fstatat(parentDirFd, cName, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			return fuse.ToStatus(err)
		}
		if st.Mode&0700 != 0700 {
			tlog.Debug.Printf("Rmdir: permWorkaround")
			permWorkaround = true
			// This cast is needed on Darwin, where st.Mode is uint16.
			origMode = uint32(st.Mode)
			err = syscallcompat.FchmodatNofollow(parentDirFd, cName, origMode|0700)
			if err != nil {
				tlog.Debug.Printf("Rmdir: permWorkaround: chmod failed: %v", err)
				return fuse.ToStatus(err)
			}
		}
	}
	dirfd, err := syscallcompat.Openat(parentDirFd, cName,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		tlog.Debug.Printf("Rmdir: Open: %v", err)
		return fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	// Undo the chmod if removing the directory failed. This must run before
	// closing dirfd, so defer it after (defer is LIFO).
	if permWorkaround {
		defer func() {
			if code != fuse.OK {
				err = unix.Fchmod(dirfd, origMode)
				if err != nil {
					tlog.Warn.Printf("Rmdir: permWorkaround: rollback failed: %v", err)
				}
			}
		}()
	}
retry:
	// Check directory contents
	children, err := syscallcompat.Getdents(dirfd)
	if err == io.EOF {
		// The directory is empty
		tlog.Warn.Printf("Rmdir: %q: %s is missing", cName, nametransform.DirIVFilename)
		err = unix.Unlinkat(parentDirFd, cName, unix.AT_REMOVEDIR)
		return fuse.ToStatus(err)
	}
	if err != nil {
		tlog.Warn.Printf("Rmdir: Readdirnames: %v", err)
		return fuse.ToStatus(err)
	}
	// MacOS sprinkles .DS_Store files everywhere. This is hard to avoid for
	// users, so handle it transparently here.
	if runtime.GOOS == "darwin" && len(children) <= 2 && haveDsstore(children) {
		err = unix.Unlinkat(dirfd, dsStoreName, 0)
		if err != nil {
			tlog.Warn.Printf("Rmdir: failed to delete blocking file %q: %v", dsStoreName, err)
			return fuse.ToStatus(err)
		}
		tlog.Warn.Printf("Rmdir: had to delete blocking file %q", dsStoreName)
		goto retry
	}
	// If the directory is not empty besides gocryptfs.diriv, do not even
	// attempt the dance around gocryptfs.diriv.
	if len(children) > 1 {
		return fuse.ToStatus(syscall.ENOTEMPTY)
	}
	// Move "gocryptfs.diriv" to the parent dir as "gocryptfs.diriv.rmdir.XYZ"
	tmpName := fmt.Sprintf("%s.rmdir.%d", nametransform.DirIVFilename, cryptocore.RandUint64())
	tlog.Debug.Printf("Rmdir: Renaming %s to %s", nametransform.DirIVFilename, tmpName)
	// The directory is in an inconsistent state between rename and rmdir.
	// Protect against concurrent readers.
	fs.dirIVLock.Lock()
	defer fs.dirIVLock.Unlock()
	err = syscallcompat.Renameat(dirfd, nametransform.DirIVFilename,
		parentDirFd, tmpName)
	if err != nil {
		tlog.Warn.Printf("Rmdir: Renaming %s to %s failed: %v",
			nametransform.DirIVFilename, tmpName, err)
		return fuse.ToStatus(err)
	}
	// Actual Rmdir
	err = syscallcompat.Unlinkat(parentDirFd, cName, unix.AT_REMOVEDIR)
	if err != nil {
		// This can happen if another file in the directory was created in the
		// meantime, undo the rename
		err2 := syscallcompat.Renameat(parentDirFd, tmpName,
			dirfd, nametransform.DirIVFilename)
		if err2 != nil {
			tlog.Warn.Printf("Rmdir: Rename rollback failed: %v", err2)
		}
		return fuse.ToStatus(err)
	}
	// Delete "gocryptfs.diriv.rmdir.XYZ"
	err = syscallcompat.Unlinkat(parentDirFd, tmpName, 0)
	if err != nil {
		tlog.Warn.Printf("Rmdir: Could not clean up %s: %v", tmpName, err)
	}
	// Delete .name file
	if nametransform.IsLongContent(cName) {
		nametransform.DeleteLongNameAt(parentDirFd, cName)
	}
	return fuse.OK
}

// OpenDir - FUSE call
//
// This function is symlink-safe through use of openBackingDir() and
// ReadDirIVAt().
func (fs *FS) OpenDir(dirName string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	tlog.Debug.Printf("OpenDir(%s)", dirName)
	parentDirFd, cDirName, err := fs.openBackingDir(dirName)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	defer syscall.Close(parentDirFd)
	// Read ciphertext directory
	var cipherEntries []fuse.DirEntry
	var status fuse.Status
	fd, err := syscallcompat.Openat(parentDirFd, cDirName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
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
		// Read the DirIV from disk
		cachedIV, err = nametransform.ReadDirIVAt(fd)
		if err != nil {
			// The directory itself does not exist
			if err == syscall.ENOENT {
				return nil, fuse.ENOENT
			}
			// Any other problem warrants an error message
			tlog.Warn.Printf("OpenDir %q: could not read %s: %v", cDirName, nametransform.DirIVFilename, err)
			return nil, fuse.EIO
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
			cNameLong, err := nametransform.ReadLongNameAt(fd, cName)
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
