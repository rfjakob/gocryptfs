package syscallcompat

import (
	"bytes"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"
)

// PATH_MAX is the maximum allowed path length on Linux.
// It is not defined on Darwin, so we use the Linux value.
const PATH_MAX = 4096

// Readlinkat is a convenience wrapper around unix.Readlinkat() that takes
// care of buffer sizing. Implemented like os.Readlink().
func Readlinkat(dirfd int, path string) (string, error) {
	// Allocate the buffer exponentially like os.Readlink does.
	for bufsz := 128; ; bufsz *= 2 {
		buf := make([]byte, bufsz)
		n, err := unix.Readlinkat(dirfd, path, buf)
		if err != nil {
			return "", err
		}
		if n < bufsz {
			return string(buf[0:n]), nil
		}
	}
}

// Faccessat exists both in Linux and in MacOS 10.10+, but the Linux version
// DOES NOT support any flags. Emulate AT_SYMLINK_NOFOLLOW like glibc does.
func Faccessat(dirfd int, path string, mode uint32) error {
	var st unix.Stat_t
	err := Fstatat(dirfd, path, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		// Pretend that a symlink is always accessible
		return nil
	}
	return unix.Faccessat(dirfd, path, mode, 0)
}

// Linkat exists both in Linux and in MacOS 10.10+.
func Linkat(olddirfd int, oldpath string, newdirfd int, newpath string, flags int) (err error) {
	return unix.Linkat(olddirfd, oldpath, newdirfd, newpath, flags)
}

const XATTR_SIZE_MAX = 65536

// Make the buffer 1kB bigger so we can detect overflows
const XATTR_BUFSZ = XATTR_SIZE_MAX + 1024

// Fgetxattr is a wrapper around unix.Fgetxattr that handles the buffer sizing.
func Fgetxattr(fd int, attr string) (val []byte, err error) {
	// If the buffer is too small to fit the value, Linux and MacOS react
	// differently:
	// Linux: returns an ERANGE error and "-1" bytes.
	// MacOS: truncates the value and returns "size" bytes.
	//
	// We choose the simple approach of buffer that is bigger than the limit on
	// Linux, and return an error for everything that is bigger (which can
	// only happen on MacOS).
	//
	// See https://github.com/pkg/xattr for a smarter solution.
	// TODO: smarter buffer sizing?
	buf := make([]byte, XATTR_BUFSZ)
	sz, err := unix.Fgetxattr(fd, attr, buf)
	if err == syscall.ERANGE {
		// Do NOT return ERANGE - the user might retry ad inifinitum!
		return nil, syscall.EOVERFLOW
	}
	if err != nil {
		return nil, err
	}
	if sz >= XATTR_SIZE_MAX {
		return nil, syscall.EOVERFLOW
	}
	// Copy only the actually used bytes to a new (smaller) buffer
	// so "buf" never leaves the function and can be allocated on the stack.
	val = make([]byte, sz)
	copy(val, buf)
	return val, nil
}

// Lgetxattr is a wrapper around unix.Lgetxattr that handles the buffer sizing.
func Lgetxattr(path string, attr string) (val []byte, err error) {
	// See the buffer sizing comments in Fgetxattr.
	// TODO: smarter buffer sizing?
	buf := make([]byte, XATTR_BUFSZ)
	sz, err := unix.Lgetxattr(path, attr, buf)
	if err == syscall.ERANGE {
		// Do NOT return ERANGE - the user might retry ad inifinitum!
		return nil, syscall.EOVERFLOW
	}
	if err != nil {
		return nil, err
	}
	if sz >= XATTR_SIZE_MAX {
		return nil, syscall.EOVERFLOW
	}
	// Copy only the actually used bytes to a new (smaller) buffer
	// so "buf" never leaves the function and can be allocated on the stack.
	val = make([]byte, sz)
	copy(val, buf)
	return val, nil
}

// Flistxattr is a wrapper for unix.Flistxattr that handles buffer sizing and
// parsing the returned blob to a string slice.
func Flistxattr(fd int) (attrs []string, err error) {
	// See the buffer sizing comments in Fgetxattr.
	// TODO: smarter buffer sizing?
	buf := make([]byte, XATTR_BUFSZ)
	sz, err := unix.Flistxattr(fd, buf)
	if err == syscall.ERANGE {
		// Do NOT return ERANGE - the user might retry ad inifinitum!
		return nil, syscall.EOVERFLOW
	}
	if err != nil {
		return nil, err
	}
	if sz >= XATTR_SIZE_MAX {
		return nil, syscall.EOVERFLOW
	}
	attrs = parseListxattrBlob(buf[:sz])
	return attrs, nil
}

// Llistxattr is a wrapper for unix.Llistxattr that handles buffer sizing and
// parsing the returned blob to a string slice.
func Llistxattr(path string) (attrs []string, err error) {
	// TODO: smarter buffer sizing?
	buf := make([]byte, XATTR_BUFSZ)
	sz, err := unix.Llistxattr(path, buf)
	if err == syscall.ERANGE {
		// Do NOT return ERANGE - the user might retry ad inifinitum!
		return nil, syscall.EOVERFLOW
	}
	if err != nil {
		return nil, err
	}
	if sz >= XATTR_SIZE_MAX {
		return nil, syscall.EOVERFLOW
	}
	attrs = parseListxattrBlob(buf[:sz])
	return attrs, nil
}

func parseListxattrBlob(buf []byte) (attrs []string) {
	parts := bytes.Split(buf, []byte{0})
	for _, part := range parts {
		if len(part) == 0 {
			// Last part is empty, ignore
			continue
		}
		attrs = append(attrs, string(part))
	}
	return attrs
}

// OpenatUser runs the Openat syscall in the context of a different user.
func OpenatUser(dirfd int, path string, flags int, mode uint32, context *fuse.Context) (fd int, err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = syscall.Setregid(-1, int(context.Owner.Gid))
		if err != nil {
			return -1, err
		}
		defer syscall.Setregid(-1, 0)

		err = syscall.Setreuid(-1, int(context.Owner.Uid))
		if err != nil {
			return -1, err
		}
		defer syscall.Setreuid(-1, 0)
	}

	return Openat(dirfd, path, flags, mode)
}

// MknodatUser runs the Mknodat syscall in the context of a different user.
func MknodatUser(dirfd int, path string, mode uint32, dev int, context *fuse.Context) (err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = syscall.Setregid(-1, int(context.Owner.Gid))
		if err != nil {
			return err
		}
		defer syscall.Setregid(-1, 0)

		err = syscall.Setreuid(-1, int(context.Owner.Uid))
		if err != nil {
			return err
		}
		defer syscall.Setreuid(-1, 0)
	}

	return Mknodat(dirfd, path, mode, dev)
}

// SymlinkatUser runs the Symlinkat syscall in the context of a different user.
func SymlinkatUser(oldpath string, newdirfd int, newpath string, context *fuse.Context) (err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = syscall.Setregid(-1, int(context.Owner.Gid))
		if err != nil {
			return err
		}
		defer syscall.Setregid(-1, 0)

		err = syscall.Setreuid(-1, int(context.Owner.Uid))
		if err != nil {
			return err
		}
		defer syscall.Setreuid(-1, 0)
	}

	return Symlinkat(oldpath, newdirfd, newpath)
}

// MkdiratUser runs the Mkdirat syscall in the context of a different user.
func MkdiratUser(dirfd int, path string, mode uint32, context *fuse.Context) (err error) {
	if context != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err = syscall.Setregid(-1, int(context.Owner.Gid))
		if err != nil {
			return err
		}
		defer syscall.Setregid(-1, 0)

		err = syscall.Setreuid(-1, int(context.Owner.Uid))
		if err != nil {
			return err
		}
		defer syscall.Setreuid(-1, 0)
	}

	return Mkdirat(dirfd, path, mode)
}
