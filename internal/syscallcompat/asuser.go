package syscallcompat

import (
	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// OpenatUser runs the Openat syscall in the context of a different user.
// It switches the current thread to the new user, performs the syscall,
// and switches back.
//
// If `context` is nil, this function behaves like ordinary Openat (no
// user switching).
func OpenatUser(dirfd int, path string, flags int, mode uint32, context *fuse.Context) (fd int, err error) {
	f := func() (int, error) {
		return Openat(dirfd, path, flags, mode)
	}
	return asUser(f, context)
}

// MknodatUser runs the Mknodat syscall in the context of a different user.
// If `context` is nil, this function behaves like ordinary Mknodat.
//
// See OpenatUser() for how this works.
func MknodatUser(dirfd int, path string, mode uint32, dev int, context *fuse.Context) (err error) {
	f := func() (int, error) {
		err := Mknodat(dirfd, path, mode, dev)
		return -1, err
	}
	_, err = asUser(f, context)
	return err
}

// SymlinkatUser runs the Symlinkat syscall in the context of a different user.
// If `context` is nil, this function behaves like ordinary Symlinkat.
//
// See OpenatUser() for how this works.
func SymlinkatUser(oldpath string, newdirfd int, newpath string, context *fuse.Context) (err error) {
	f := func() (int, error) {
		err := unix.Symlinkat(oldpath, newdirfd, newpath)
		return -1, err
	}
	_, err = asUser(f, context)
	return err
}

// MkdiratUser runs the Mkdirat syscall in the context of a different user.
// If `context` is nil, this function behaves like ordinary Mkdirat.
//
// See OpenatUser() for how this works.
func MkdiratUser(dirfd int, path string, mode uint32, context *fuse.Context) (err error) {
	f := func() (int, error) {
		err := unix.Mkdirat(dirfd, path, mode)
		return -1, err
	}
	_, err = asUser(f, context)
	return err
}
