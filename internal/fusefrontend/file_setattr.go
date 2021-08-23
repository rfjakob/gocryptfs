package fusefrontend

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

func (f *File) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) (errno syscall.Errno) {
	errno = f.setAttr(ctx, in)
	if errno != 0 {
		return errno
	}
	return f.Getattr(ctx, out)
}

func (f *File) setAttr(ctx context.Context, in *fuse.SetAttrIn) (errno syscall.Errno) {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	if f.released {
		tlog.Warn.Printf("ino%d fh%d: Truncate on released file", f.qIno.Ino, f.intFd())
		return syscall.EBADF
	}
	f.fileTableEntry.ContentLock.Lock()
	defer f.fileTableEntry.ContentLock.Unlock()

	// fchmod(2)
	if mode, ok := in.GetMode(); ok {
		errno = fs.ToErrno(syscall.Fchmod(f.intFd(), mode))
		if errno != 0 {
			return errno
		}
	}

	// fchown(2)
	uid32, uOk := in.GetUID()
	gid32, gOk := in.GetGID()
	if uOk || gOk {
		uid := -1
		gid := -1

		if uOk {
			uid = int(uid32)
		}
		if gOk {
			gid = int(gid32)
		}
		errno = fs.ToErrno(syscall.Fchown(f.intFd(), uid, gid))
		if errno != 0 {
			return errno
		}
	}

	// utimens(2)
	mtime, mok := in.GetMTime()
	atime, aok := in.GetATime()
	if mok || aok {
		ap := &atime
		mp := &mtime
		if !aok {
			ap = nil
		}
		if !mok {
			mp = nil
		}
		errno = fs.ToErrno(syscallcompat.FutimesNano(f.intFd(), ap, mp))
		if errno != 0 {
			return errno
		}
	}

	// truncate(2)
	if sz, ok := in.GetSize(); ok {
		errno = syscall.Errno(f.truncate(sz))
		if errno != 0 {
			return errno
		}
	}
	return 0
}
