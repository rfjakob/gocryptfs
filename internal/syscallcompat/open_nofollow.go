package syscallcompat

import (
	"path/filepath"
	"strings"
	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// OpenNofollow opens the file/dir at "relPath" in a way that is secure against
// symlink attacks. Symlinks that are part of "relPath" are never followed.
// This function is implemented by walking the directory tree, starting at
// "baseDir", using the Openat syscall with the O_NOFOLLOW flag.
// Symlinks that are part of the "baseDir" path are followed.
func OpenNofollow(baseDir string, relPath string, flags int, mode uint32) (fd int, err error) {
	if !filepath.IsAbs(baseDir) {
		tlog.Warn.Printf("BUG: OpenNofollow called with relative baseDir=%q", baseDir)
		return -1, unix.EINVAL
	}
	if filepath.IsAbs(relPath) {
		tlog.Warn.Printf("BUG: OpenNofollow called with absolute relPath=%q", relPath)
		return -1, unix.EINVAL
	}
	// Open the base dir (following symlinks)
	dirfd, err := unix.Open(baseDir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, err
	}
	// Caller wanted to open baseDir itself?
	if relPath == "" {
		return dirfd, nil
	}
	// Split the path into components and separate intermediate directories
	// and the final basename
	parts := strings.Split(relPath, "/")
	dirs := parts[:len(parts)-1]
	final := parts[len(parts)-1]
	// Walk intermediate directories
	var dirfd2 int
	for _, name := range dirs {
		dirfd2, err = Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		unix.Close(dirfd)
		if err != nil {
			return -1, err
		}
		dirfd = dirfd2
	}
	defer unix.Close(dirfd)
	// Open the final component with the flags and permissions requested by
	// the user plus forced NOFOLLOW.
	return Openat(dirfd, final, flags|unix.O_NOFOLLOW, mode)
}
