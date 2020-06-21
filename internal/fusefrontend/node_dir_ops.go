package fusefrontend

import (
	"context"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// mkdirWithIv - create a new directory and corresponding diriv file. dirfd
// should be a handle to the parent directory, cName is the name of the new
// directory and mode specifies the access permissions to use.
func (n *Node) mkdirWithIv(dirfd int, cName string, mode uint32, caller *fuse.Caller) error {
	rn := n.rootNode()
	// Between the creation of the directory and the creation of gocryptfs.diriv
	// the directory is inconsistent. Take the lock to prevent other readers
	// from seeing it.
	rn.dirIVLock.Lock()
	defer rn.dirIVLock.Unlock()
	err := syscallcompat.MkdiratUser(dirfd, cName, mode, caller)
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
func (n *Node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	rn := n.rootNode()
	newPath := filepath.Join(n.path(), name)
	if rn.isFiltered(newPath) {
		return nil, syscall.EPERM
	}
	dirfd, cName, err := rn.openBackingDir(newPath)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(dirfd)
	var caller *fuse.Caller
	if rn.args.PreserveOwner {
		caller, _ = fuse.FromContext(ctx)
	}
	if rn.args.PlaintextNames {
		err = syscallcompat.MkdiratUser(dirfd, cName, mode, caller)
		return nil, fs.ToErrno(err)
	}

	// We need write and execute permissions to create gocryptfs.diriv.
	// Also, we need read permissions to open the directory (to avoid
	// race-conditions between getting and setting the mode).
	origMode := mode
	mode = mode | 0700

	// Handle long file name
	if nametransform.IsLongContent(cName) {
		// Create ".name"
		err = rn.nameTransform.WriteLongNameAt(dirfd, cName, newPath)
		if err != nil {
			return nil, fs.ToErrno(err)
		}

		// Create directory
		err = rn.mkdirWithIv(dirfd, cName, mode, caller)
		if err != nil {
			nametransform.DeleteLongNameAt(dirfd, cName)
			return nil, fs.ToErrno(err)
		}
	} else {
		err = rn.mkdirWithIv(dirfd, cName, mode, caller)
		if err != nil {
			return nil, fs.ToErrno(err)
		}
	}

	fd, err := syscallcompat.Openat(dirfd, cName,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		tlog.Warn.Printf("Mkdir %q: Openat failed: %v", cName, err)
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(fd)

	// Get unique inode number
	var st syscall.Stat_t
	err = syscall.Fstat(fd, &st)
	if err != nil {
		tlog.Warn.Printf("Mkdir %q: Fstat failed: %v", cName, err)
		return nil, fs.ToErrno(err)
	}
	rn.inoMap.TranslateStat(&st)
	out.Attr.FromStat(&st)
	// Create child node
	id := fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  1,
		Ino:  st.Ino,
	}
	node := &Node{}
	ch := n.NewInode(ctx, node, id)

	// Set mode
	if origMode != mode {
		// Preserve SGID bit if it was set due to inheritance.
		origMode = uint32(st.Mode&^0777) | origMode
		err = syscall.Fchmod(fd, origMode)
		if err != nil {
			tlog.Warn.Printf("Mkdir %q: Fchmod %#o -> %#o failed: %v", cName, mode, origMode, err)
		}
	}

	return ch, 0
}

func (n *Node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	rn := n.rootNode()
	p := n.path()
	dirName := filepath.Base(p)
	parentDirFd, cDirName, err := rn.openBackingDir(p)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(parentDirFd)

	// Read ciphertext directory
	var cipherEntries []fuse.DirEntry
	fd, err := syscallcompat.Openat(parentDirFd, cDirName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(fd)
	cipherEntries, err = syscallcompat.Getdents(fd)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	// Get DirIV (stays nil if PlaintextNames is used)
	var cachedIV []byte
	if !rn.args.PlaintextNames {
		// Read the DirIV from disk
		cachedIV, err = nametransform.ReadDirIVAt(fd)
		if err != nil {
			tlog.Warn.Printf("OpenDir %q: could not read %s: %v", cDirName, nametransform.DirIVFilename, err)
			return nil, syscall.EIO
		}
	}
	// Decrypted directory entries
	var plain []fuse.DirEntry
	// Filter and decrypt filenames
	for i := range cipherEntries {
		cName := cipherEntries[i].Name
		if dirName == "." && cName == configfile.ConfDefaultName {
			// silently ignore "gocryptfs.conf" in the top level dir
			continue
		}
		if rn.args.PlaintextNames {
			plain = append(plain, cipherEntries[i])
			continue
		}
		if cName == nametransform.DirIVFilename {
			// silently ignore "gocryptfs.diriv" everywhere if dirIV is enabled
			continue
		}
		// Handle long file name
		isLong := nametransform.LongNameNone
		if rn.args.LongNames {
			isLong = nametransform.NameType(cName)
		}
		if isLong == nametransform.LongNameContent {
			cNameLong, err := nametransform.ReadLongNameAt(fd, cName)
			if err != nil {
				tlog.Warn.Printf("OpenDir %q: invalid entry %q: Could not read .name: %v",
					cDirName, cName, err)
				rn.reportMitigatedCorruption(cName)
				continue
			}
			cName = cNameLong
		} else if isLong == nametransform.LongNameFilename {
			// ignore "gocryptfs.longname.*.name"
			continue
		}
		name, err := rn.nameTransform.DecryptName(cName, cachedIV)
		if err != nil {
			tlog.Warn.Printf("OpenDir %q: invalid entry %q: %v",
				cDirName, cName, err)
			rn.reportMitigatedCorruption(cName)
			continue
		}
		// Override the ciphertext name with the plaintext name but reuse the rest
		// of the structure
		cipherEntries[i].Name = name
		plain = append(plain, cipherEntries[i])
	}

	return fs.NewListDirStream(plain), 0
}
