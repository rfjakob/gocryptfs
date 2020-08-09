package fusefrontend_reverse

import (
	"context"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

var _ = (fs.NodeOpener)((*VirtualConfNode)(nil))

type VirtualConfNode struct {
	fs.Inode

	path string
}

func (n *VirtualConfNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	fd, err := syscall.Open(n.path, syscall.O_RDONLY, 0)
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}
	fh = &VirtualConfFile{fd: fd}
	return
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
	res = fuse.ReadResultFd(uintptr(f.fd), off, len(buf))
	return
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
