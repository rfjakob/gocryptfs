package fusefrontend

import (
	"context"
	"os"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// mangleOpenCreateFlags is used by Create() and Open() to convert the open flags the user
// wants to the flags we internally use to open the backing file using Openat().
// The returned flags always contain O_NOFOLLOW/O_SYMLINK.
func mangleOpenCreateFlags(flags uint32) (newFlags int) {
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
	// Create and Open are two separate FUSE operations, so O_CREAT should usually not
	// be part of the Open() flags. Create() will add O_CREAT back itself.
	newFlags = newFlags &^ syscall.O_CREAT
	// We always want O_NOFOLLOW/O_SYMLINK to be safe against symlink races
	newFlags |= syscallcompat.OpenatFlagNofollowSymlink
	return newFlags
}

// Open - FUSE call. Open already-existing file.
//
// Symlink-safe through Openat().
func (n *Node) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	rn := n.rootNode()
	newFlags := mangleOpenCreateFlags(flags)
	// Taking this lock makes sure we don't race openWriteOnlyFile()
	rn.openWriteOnlyLock.RLock()
	defer rn.openWriteOnlyLock.RUnlock()

	if rn.args.KernelCache {
		fuseFlags = fuse.FOPEN_KEEP_CACHE
	}

	// Open backing file
	fd, err := syscallcompat.Openat(dirfd, cName, newFlags, 0)
	// Handle a few specific errors
	if err != nil {
		if err == syscall.EMFILE {
			var lim syscall.Rlimit
			syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
			tlog.Warn.Printf("Open %q: too many open files. Current \"ulimit -n\": %d", cName, lim.Cur)
		}
		if err == syscall.EACCES && (int(flags)&syscall.O_ACCMODE) == syscall.O_WRONLY {
			fd, err = rn.openWriteOnlyFile(dirfd, cName, newFlags)
		}
	}
	// Could not handle the error? Bail out
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}
	fh, _, errno = NewFile(fd, cName, rn)
	return fh, fuseFlags, errno
}

// Create - FUSE call. Creates a new file.
//
// Symlink-safe through the use of Openat().
func (n *Node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	dirfd, cName, errno := n.prepareAtSyscall(name)
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	var err error
	fd := -1
	// Make sure context is nil if we don't want to preserve the owner
	rn := n.rootNode()
	if !rn.args.PreserveOwner {
		ctx = nil
	}
	newFlags := mangleOpenCreateFlags(flags)
	// Handle long file name
	ctx2 := toFuseCtx(ctx)
	if !rn.args.PlaintextNames && nametransform.IsLongContent(cName) {
		// Create ".name"
		err = rn.nameTransform.WriteLongNameAt(dirfd, cName, name)
		if err != nil {
			return nil, nil, 0, fs.ToErrno(err)
		}
		// Create content
		fd, err = syscallcompat.OpenatUser(dirfd, cName, newFlags|syscall.O_CREAT|syscall.O_EXCL, mode, ctx2)
		if err != nil {
			nametransform.DeleteLongNameAt(dirfd, cName)
		}
	} else {
		// Create content, normal (short) file name
		fd, err = syscallcompat.OpenatUser(dirfd, cName, newFlags|syscall.O_CREAT|syscall.O_EXCL, mode, ctx2)
	}
	if err != nil {
		// xfstests generic/488 triggers this
		if err == syscall.EMFILE {
			var lim syscall.Rlimit
			syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
			tlog.Warn.Printf("Create %q: too many open files. Current \"ulimit -n\": %d", cName, lim.Cur)
		}
		return nil, nil, 0, fs.ToErrno(err)
	}

	fh, st, errno := NewFile(fd, cName, rn)
	if errno != 0 {
		return
	}

	inode = n.newChild(ctx, st, out)

	if rn.args.ForceOwner != nil {
		out.Owner = *rn.args.ForceOwner
	}

	return inode, fh, fuseFlags, errno
}
