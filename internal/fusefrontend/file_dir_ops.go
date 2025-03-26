package fusefrontend

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

func (n *Node) OpendirHandle(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	var fd int = -1
	var fdDup int = -1
	var file *File
	var dirIV []byte
	var ds fs.DirStream
	rn := n.rootNode()

	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	// Open backing directory
	fd, err := syscallcompat.Openat(dirfd, cName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}

	// NewLoopbackDirStreamFd gets its own fd to untangle Release vs Releasedir
	fdDup, err = syscall.Dup(fd)

	if err != nil {
		errno = fs.ToErrno(err)
		goto err_out
	}

	ds, errno = fs.NewLoopbackDirStreamFd(fdDup)
	if errno != 0 {
		goto err_out
	}

	if !rn.args.PlaintextNames {
		// Read the DirIV from disk
		dirIV, err = rn.nameTransform.ReadDirIVAt(fd)
		if err != nil {
			tlog.Warn.Printf("OpendirHandle: could not read %s: %v", nametransform.DirIVFilename, err)
			errno = syscall.EIO
			goto err_out
		}
	}

	file, _, errno = NewFile(fd, cName, rn)
	if errno != 0 {
		goto err_out
	}

	file.dirHandle = &DirHandle{
		ds:        ds,
		dirIV:     dirIV,
		isRootDir: n.IsRoot(),
	}

	return file, fuseFlags, errno

err_out:
	if fd >= 0 {
		syscall.Close(fd)
	}
	if fdDup >= 0 {
		syscall.Close(fdDup)
	}
	if errno == 0 {
		tlog.Warn.Printf("BUG: OpendirHandle: err_out called with errno == 0")
		errno = syscall.EIO
	}
	return nil, 0, errno
}

type DirHandle struct {
	// Content of gocryptfs.diriv. nil if plaintextnames is used.
	dirIV []byte

	isRootDir bool

	// fs.loopbackDirStream with a private dup of the file descriptor
	ds fs.FileHandle
}

var _ = (fs.FileReleasedirer)((*File)(nil))

func (f *File) Releasedir(ctx context.Context, flags uint32) {
	// Does its own locking
	f.dirHandle.ds.(fs.FileReleasedirer).Releasedir(ctx, flags)
	// Does its own locking
	f.Release(ctx)
}

var _ = (fs.FileSeekdirer)((*File)(nil))

func (f *File) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	return f.dirHandle.ds.(fs.FileSeekdirer).Seekdir(ctx, off)
}

var _ = (fs.FileFsyncdirer)((*File)(nil))

func (f *File) Fsyncdir(ctx context.Context, flags uint32) syscall.Errno {
	return f.dirHandle.ds.(fs.FileFsyncdirer).Fsyncdir(ctx, flags)
}

var _ = (fs.FileReaddirenter)((*File)(nil))

// This function is symlink-safe through use of openBackingDir() and
// ReadDirIVAt().
func (f *File) Readdirent(ctx context.Context) (entry *fuse.DirEntry, errno syscall.Errno) {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	for {
		entry, errno = f.dirHandle.ds.(fs.FileReaddirenter).Readdirent(ctx)
		if errno != 0 || entry == nil {
			return
		}

		cName := entry.Name
		if cName == "." || cName == ".." {
			// We want these as-is
			return
		}
		if f.dirHandle.isRootDir && cName == configfile.ConfDefaultName {
			// silently ignore "gocryptfs.conf" in the top level dir
			continue
		}
		if f.rootNode.args.PlaintextNames {
			return
		}
		if !f.rootNode.args.DeterministicNames && cName == nametransform.DirIVFilename {
			// silently ignore "gocryptfs.diriv" everywhere if dirIV is enabled
			continue
		}
		// Handle long file name
		isLong := nametransform.LongNameNone
		if f.rootNode.args.LongNames {
			isLong = nametransform.NameType(cName)
		}
		if isLong == nametransform.LongNameContent {
			cNameLong, err := nametransform.ReadLongNameAt(f.intFd(), cName)
			if err != nil {
				tlog.Warn.Printf("Readdirent: incomplete entry %q: Could not read .name: %v",
					cName, err)
				f.rootNode.reportMitigatedCorruption(cName)
				continue
			}
			cName = cNameLong
		} else if isLong == nametransform.LongNameFilename {
			// ignore "gocryptfs.longname.*.name"
			continue
		}
		name, err := f.rootNode.nameTransform.DecryptName(cName, f.dirHandle.dirIV)
		if err != nil {
			tlog.Warn.Printf("Readdirent: could not decrypt entry %q: %v",
				cName, err)
			f.rootNode.reportMitigatedCorruption(cName)
			continue
		}
		// Override the ciphertext name with the plaintext name but reuse the rest
		// of the structure
		entry.Name = name
		return
	}
}
