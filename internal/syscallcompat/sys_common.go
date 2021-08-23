package syscallcompat

import (
	"bytes"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
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

// Openat wraps the Openat syscall.
// Retries on EINTR.
func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	if flags&syscall.O_CREAT != 0 {
		// O_CREAT should be used with O_EXCL. O_NOFOLLOW has no effect with O_EXCL.
		if flags&syscall.O_EXCL == 0 {
			tlog.Warn.Printf("Openat: O_CREAT without O_EXCL: flags = %#x", flags)
			flags |= syscall.O_EXCL
		}
	} else {
		// If O_CREAT is not used, we should use O_NOFOLLOW
		if flags&syscall.O_NOFOLLOW == 0 {
			tlog.Warn.Printf("Openat: O_NOFOLLOW missing: flags = %#x", flags)
			flags |= syscall.O_NOFOLLOW
		}
	}
	fd, err = retryEINTR2(func() (int, error) {
		return unix.Openat(dirfd, path, flags, mode)
	})
	return fd, err
}

// Fchownat syscall.
func Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error) {
	// Why would we ever want to call this without AT_SYMLINK_NOFOLLOW?
	if flags&unix.AT_SYMLINK_NOFOLLOW == 0 {
		tlog.Warn.Printf("Fchownat: adding missing AT_SYMLINK_NOFOLLOW flag")
		flags |= unix.AT_SYMLINK_NOFOLLOW
	}
	return unix.Fchownat(dirfd, path, uid, gid, flags)
}

// Fstatat syscall.
// Retries on EINTR.
func Fstatat(dirfd int, path string, stat *unix.Stat_t, flags int) (err error) {
	// Why would we ever want to call this without AT_SYMLINK_NOFOLLOW?
	if flags&unix.AT_SYMLINK_NOFOLLOW == 0 {
		tlog.Warn.Printf("Fstatat: adding missing AT_SYMLINK_NOFOLLOW flag")
		flags |= unix.AT_SYMLINK_NOFOLLOW
	}
	err = retryEINTR(func() error {
		return unix.Fstatat(dirfd, path, stat, flags)
	})
	return err
}

// Fstatat2 is a more convenient version of Fstatat. It allocates a Stat_t
// for you and also handles the Unix2syscall conversion.
// Retries on EINTR.
func Fstatat2(dirfd int, path string, flags int) (*syscall.Stat_t, error) {
	var stUnix unix.Stat_t
	err := Fstatat(dirfd, path, &stUnix, flags)
	if err != nil {
		return nil, err
	}
	st := Unix2syscall(stUnix)
	return &st, nil
}

const XATTR_SIZE_MAX = 65536

// Make the buffer 1kB bigger so we can detect overflows. Unfortunately,
// slices larger than 64kB are always allocated on the heap.
const XATTR_BUFSZ = XATTR_SIZE_MAX + 1024

// We try with a small buffer first - this one can be allocated on the stack.
const XATTR_BUFSZ_SMALL = 500

// Fgetxattr is a wrapper around unix.Fgetxattr that handles the buffer sizing.
func Fgetxattr(fd int, attr string) (val []byte, err error) {
	fn := func(buf []byte) (int, error) {
		return unix.Fgetxattr(fd, attr, buf)
	}
	return getxattrSmartBuf(fn)
}

// Lgetxattr is a wrapper around unix.Lgetxattr that handles the buffer sizing.
func Lgetxattr(path string, attr string) (val []byte, err error) {
	fn := func(buf []byte) (int, error) {
		return unix.Lgetxattr(path, attr, buf)
	}
	return getxattrSmartBuf(fn)
}

func getxattrSmartBuf(fn func(buf []byte) (int, error)) ([]byte, error) {
	// Fastpaths. Important for security.capabilities, which gets queried a lot.
	buf := make([]byte, XATTR_BUFSZ_SMALL)
	sz, err := fn(buf)
	// Non-existing xattr
	if err == unix.ENODATA {
		return nil, err
	}
	// Underlying fs does not support security.capabilities (example: tmpfs)
	if err == unix.EOPNOTSUPP {
		return nil, err
	}
	// Small xattr
	if err == nil && sz < len(buf) {
		goto out
	}
	// Generic slowpath
	//
	// If the buffer is too small to fit the value, Linux and MacOS react
	// differently:
	// Linux: returns an ERANGE error and "-1" bytes.
	// MacOS: truncates the value and returns "size" bytes.
	//
	// We choose the simple approach of buffer that is bigger than the limit on
	// Linux, and return an error for everything that is bigger (which can
	// only happen on MacOS).
	buf = make([]byte, XATTR_BUFSZ)
	sz, err = fn(buf)
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
out:
	// Copy only the actually used bytes to a new (smaller) buffer
	// so "buf" never leaves the function and can be allocated on the stack.
	val := make([]byte, sz)
	copy(val, buf)
	return val, nil
}

// Flistxattr is a wrapper for unix.Flistxattr that handles buffer sizing and
// parsing the returned blob to a string slice.
func Flistxattr(fd int) (attrs []string, err error) {
	// See the buffer sizing comments in getxattrSmartBuf.
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
