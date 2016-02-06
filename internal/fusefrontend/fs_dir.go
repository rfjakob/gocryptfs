package fusefrontend

// Mkdir and Rmdir

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/toggledlog"
)

func (fs *FS) Mkdir(relPath string, mode uint32, context *fuse.Context) (code fuse.Status) {
	if fs.isFiltered(relPath) {
		return fuse.EPERM
	}
	encPath, err := fs.getBackingPath(relPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	if !fs.args.DirIV {
		return fuse.ToStatus(os.Mkdir(encPath, os.FileMode(mode)))
	}

	// We need write and execute permissions to create gocryptfs.diriv
	origMode := mode
	mode = mode | 0300

	// The new directory may take the place of an older one that is still in the cache
	fs.nameTransform.DirIVCache.Clear()
	// Create directory
	fs.dirIVLock.Lock()
	defer fs.dirIVLock.Unlock()
	err = os.Mkdir(encPath, os.FileMode(mode))
	if err != nil {
		return fuse.ToStatus(err)
	}
	// Create gocryptfs.diriv inside
	err = nametransform.WriteDirIV(encPath)
	if err != nil {
		// This should not happen
		toggledlog.Warn.Printf("Mkdir: WriteDirIV failed: %v", err)
		err2 := syscall.Rmdir(encPath)
		if err2 != nil {
			toggledlog.Warn.Printf("Mkdir: Rmdir rollback failed: %v", err2)
		}
		return fuse.ToStatus(err)
	}

	// Set permissions back to what the user wanted
	if origMode != mode {
		err = os.Chmod(encPath, os.FileMode(origMode))
		if err != nil {
			toggledlog.Warn.Printf("Mkdir: Chmod failed: %v", err)
		}
	}

	return fuse.OK
}

func (fs *FS) Rmdir(name string, context *fuse.Context) (code fuse.Status) {
	encPath, err := fs.getBackingPath(name)
	if err != nil {
		return fuse.ToStatus(err)
	}
	if !fs.args.DirIV {
		return fuse.ToStatus(syscall.Rmdir(encPath))
	}

	// If the directory is not empty besides gocryptfs.diriv, do not even
	// attempt the dance around gocryptfs.diriv.
	fd, err := os.Open(encPath)
	if perr, ok := err.(*os.PathError); ok && perr.Err == syscall.EACCES {
		// We need permission to read and modify the directory
		toggledlog.Debug.Printf("Rmdir: handling EACCESS")
		fi, err2 := os.Stat(encPath)
		if err2 != nil {
			toggledlog.Debug.Printf("Rmdir: Stat: %v", err2)
			return fuse.ToStatus(err2)
		}
		origMode := fi.Mode()
		newMode := origMode | 0700
		err2 = os.Chmod(encPath, newMode)
		if err2 != nil {
			toggledlog.Debug.Printf("Rmdir: Chmod failed: %v", err2)
			return fuse.ToStatus(err)
		}
		defer func() {
			if code != fuse.OK {
				// Undo the chmod if removing the directory failed
				err3 := os.Chmod(encPath, origMode)
				if err3 != nil {
					toggledlog.Warn.Printf("Rmdir: Chmod rollback failed: %v", err2)
				}
			}
		}()
		// Retry open
		fd, err = os.Open(encPath)
	}
	if err != nil {
		toggledlog.Debug.Printf("Rmdir: Open: %v", err)
		return fuse.ToStatus(err)
	}
	list, err := fd.Readdirnames(10)
	fd.Close()
	if err != nil {
		toggledlog.Debug.Printf("Rmdir: Readdirnames: %v", err)
		return fuse.ToStatus(err)
	}
	if len(list) > 1 {
		return fuse.ToStatus(syscall.ENOTEMPTY)
	} else if len(list) == 0 {
		toggledlog.Warn.Printf("Rmdir: gocryptfs.diriv missing, allowing deletion")
		return fuse.ToStatus(syscall.Rmdir(encPath))
	}

	// Move "gocryptfs.diriv" to the parent dir as "gocryptfs.diriv.rmdir.XYZ"
	dirivPath := filepath.Join(encPath, nametransform.DirIVFilename)
	parentDir := filepath.Dir(encPath)
	tmpName := fmt.Sprintf("gocryptfs.diriv.rmdir.%d", cryptocore.RandUint64())
	tmpDirivPath := filepath.Join(parentDir, tmpName)
	toggledlog.Debug.Printf("Rmdir: Renaming %s to %s", nametransform.DirIVFilename, tmpDirivPath)
	// The directory is in an inconsistent state between rename and rmdir. Protect against
	// concurrent readers.
	fs.dirIVLock.Lock()
	defer fs.dirIVLock.Unlock()
	err = os.Rename(dirivPath, tmpDirivPath)
	if err != nil {
		toggledlog.Warn.Printf("Rmdir: Renaming %s to %s failed: %v",
			nametransform.DirIVFilename, tmpDirivPath, err)
		return fuse.ToStatus(err)
	}
	// Actual Rmdir
	err = syscall.Rmdir(encPath)
	if err != nil {
		// This can happen if another file in the directory was created in the
		// meantime, undo the rename
		err2 := os.Rename(tmpDirivPath, dirivPath)
		if err2 != nil {
			toggledlog.Warn.Printf("Rmdir: Rename rollback failed: %v", err2)
		}
		return fuse.ToStatus(err)
	}
	// Delete "gocryptfs.diriv.rmdir.INODENUMBER"
	err = syscall.Unlink(tmpDirivPath)
	if err != nil {
		toggledlog.Warn.Printf("Rmdir: Could not clean up %s: %v", tmpName, err)
	}
	// The now-deleted directory may have been in the DirIV cache. Clear it.
	fs.nameTransform.DirIVCache.Clear()
	return fuse.OK
}
