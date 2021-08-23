package fusefrontend_reverse

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/pathiv"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// Node is a file or directory in the filesystem tree
// in a `gocryptfs -reverse` mount.
type Node struct {
	fs.Inode
	// isOtherFilesystem is used for --one-filesystem.
	// It is set when the device number of this file or directory
	// is different from n.rootNode().rootDev.
	isOtherFilesystem bool
}

// Lookup - FUSE call for discovering a file.
func (n *Node) Lookup(ctx context.Context, cName string, out *fuse.EntryOut) (ch *fs.Inode, errno syscall.Errno) {
	var d *dirfdPlus
	t := n.lookupFileType(cName)
	if t == typeDiriv {
		// gocryptfs.diriv
		return n.lookupDiriv(ctx, out)
	}
	rn := n.rootNode()
	if rn.args.OneFileSystem && n.isOtherFilesystem {
		// With --one-file-system, we present mountpoints as empty. That is,
		// it contains only a gocryptfs.diriv file (allowed above).
		return nil, syscall.ENOENT
	}
	if t == typeName {
		// gocryptfs.longname.*.name
		return n.lookupLongnameName(ctx, cName, out)
	} else if t == typeConfig {
		// gocryptfs.conf
		return n.lookupConf(ctx, out)
	} else if t == typeReal {
		// real file
		d, errno = n.prepareAtSyscall(cName)
		//fmt.Printf("Lookup: prepareAtSyscall -> d=%#v, errno=%d\n", d, errno)
		if errno != 0 {
			return
		}
		defer syscall.Close(d.dirfd)
	}
	// Get device number and inode number into `st`
	st, err := syscallcompat.Fstatat2(d.dirfd, d.pName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	// Create new inode and fill `out`
	ch = n.newChild(ctx, st, out)
	// Translate ciphertext size in `out.Attr.Size` to plaintext size
	if t == typeReal {
		n.translateSize(d.dirfd, cName, d.pName, &out.Attr)
	}
	return ch, 0
}

// GetAttr - FUSE call for stat()ing a file.
//
// GetAttr is symlink-safe through use of openBackingDir() and Fstatat().
func (n *Node) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) (errno syscall.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)

	st, err := syscallcompat.Fstatat2(d.dirfd, d.pName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return fs.ToErrno(err)
	}

	// Fix inode number
	rn := n.rootNode()
	rn.inoMap.TranslateStat(st)
	out.Attr.FromStat(st)

	// Translate ciphertext size in `out.Attr.Size` to plaintext size
	cName := filepath.Base(n.Path())
	n.translateSize(d.dirfd, cName, d.pName, &out.Attr)

	if rn.args.ForceOwner != nil {
		out.Owner = *rn.args.ForceOwner
	}
	return 0
}

// Readlink - FUSE call.
//
// Symlink-safe through openBackingDir() + Readlinkat().
func (n *Node) Readlink(ctx context.Context) (out []byte, errno syscall.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)

	return n.readlink(d.dirfd, d.cName, d.pName)
}

// Open - FUSE call. Open already-existing file.
//
// Symlink-safe through Openat().
func (n *Node) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)

	fd, err := syscallcompat.Openat(d.dirfd, d.pName, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}

	// Reject access if the file descriptor does not refer to a regular file.
	var st syscall.Stat_t
	err = syscall.Fstat(fd, &st)
	if err != nil {
		tlog.Warn.Printf("Open: Fstat error: %v", err)
		syscall.Close(fd)
		errno = fs.ToErrno(err)
		return
	}
	var a fuse.Attr
	a.FromStat(&st)
	if !a.IsRegular() {
		tlog.Warn.Printf("ino%d: newFile: not a regular file", st.Ino)
		syscall.Close(fd)
		errno = syscall.EACCES
		return
	}
	// See if we have that inode number already in the table
	// (even if Nlink has dropped to 1)
	var derivedIVs pathiv.FileIVs
	v, found := inodeTable.Load(st.Ino)
	if found {
		tlog.Debug.Printf("ino%d: newFile: found in the inode table", st.Ino)
		derivedIVs = v.(pathiv.FileIVs)
	} else {
		p := n.Path()
		derivedIVs = pathiv.DeriveFile(p)
		// Nlink > 1 means there is more than one path to this file.
		// Store the derived values so we always return the same data,
		// regardless of the path that is used to access the file.
		// This means that the first path wins.
		if st.Nlink > 1 {
			v, found = inodeTable.LoadOrStore(st.Ino, derivedIVs)
			if found {
				// Another thread has stored a different value before we could.
				derivedIVs = v.(pathiv.FileIVs)
			} else {
				tlog.Debug.Printf("ino%d: newFile: Nlink=%d, stored in the inode table", st.Ino, st.Nlink)
			}
		}
	}
	header := contentenc.FileHeader{
		Version: contentenc.CurrentVersion,
		ID:      derivedIVs.ID,
	}
	fh = &File{
		fd:         os.NewFile(uintptr(fd), fmt.Sprintf("fd%d", fd)),
		header:     header,
		block0IV:   derivedIVs.Block0IV,
		contentEnc: n.rootNode().contentEnc,
	}
	return
}

// StatFs - FUSE call. Returns information about the filesystem.
//
// Symlink-safe because the path is ignored.
func (n *Node) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	p := n.rootNode().args.Cipherdir
	var st syscall.Statfs_t
	err := syscall.Statfs(p, &st)
	if err != nil {
		return fs.ToErrno(err)
	}
	out.FromStatfsT(&st)
	return 0
}
