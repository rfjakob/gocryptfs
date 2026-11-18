package fusefrontend_reverse

import (
	"context"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var _ = (fs.NodeOpener)((*VirtualConfNode)(nil))
var _ = (fs.NodeGetattrer)((*VirtualConfNode)(nil))

type VirtualConfNode struct {
	fs.Inode
}

// openConf opens .gocryptfs.reverse.conf in the root of the backing
// plaintext directory and returns the fd and its stat data.
//
// The file is passed through to the user unencrypted, so we must make sure
// not to follow symlinks: otherwise, someone with write access to the
// backing directory could replace it with a symlink to /etc/shadow and
// read the target through the mount. O_NONBLOCK prevents hanging on a FIFO.
// Anything that is not a regular file is rejected.
func (rn *RootNode) openConf() (fd int, st syscall.Stat_t, err error) {
	dirfd, err := syscallcompat.Open(rn.args.Cipherdir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
	if err != nil {
		return -1, st, err
	}
	defer syscall.Close(dirfd)
	fd, err = syscallcompat.Openat(dirfd, configfile.ConfReverseName,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if err == syscall.ELOOP {
			tlog.Warn.Printf("openConf: %s is a symlink, refusing to serve it", configfile.ConfReverseName)
		}
		return -1, st, err
	}
	err = syscall.Fstat(fd, &st)
	if err != nil {
		syscall.Close(fd)
		return -1, st, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		tlog.Warn.Printf("openConf: %s is not a regular file (mode %#o), refusing to serve it",
			configfile.ConfReverseName, st.Mode)
		syscall.Close(fd)
		return -1, st, syscall.EPERM
	}
	return fd, st, nil
}

// rootNode returns the Root Node of the filesystem.
func (n *VirtualConfNode) rootNode() *RootNode {
	return n.Root().Operations().(*RootNode)
}

func (n *VirtualConfNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	fd, _, err := n.rootNode().openConf()
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}
	fh = &VirtualConfFile{fd: fd}
	return
}

func (n *VirtualConfNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	rn := n.rootNode()
	fd, st, err := rn.openConf()
	if err != nil {
		return fs.ToErrno(err)
	}
	syscall.Close(fd)
	out.FromStat(&st)
	if rn.args.ForceOwner != nil {
		out.Owner = *rn.args.ForceOwner
	}
	return 0
}

// Check that we have implemented the fs.File* interfaces
var _ = (fs.FileReader)((*VirtualConfFile)(nil))
var _ = (fs.FileReleaser)((*VirtualConfFile)(nil))

type VirtualConfFile struct {
	mu sync.Mutex
	fd int
}

func (f *VirtualConfFile) Read(ctx context.Context, buf []byte, off int64) (res fuse.ReadResult, errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := syscall.Pread(f.fd, buf, off)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return fuse.ReadResultData(buf[:n]), 0
}

func (f *VirtualConfFile) Release(ctx context.Context) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fd != -1 {
		err := syscall.Close(f.fd)
		f.fd = -1
		return fs.ToErrno(err)
	}
	return syscall.EBADF
}
