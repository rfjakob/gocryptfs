package syscallcompat

import (
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// OpenDirNofollow opens the dir at "relPath" in a way that is secure against
// symlink attacks. Symlinks that are part of "relPath" are never followed.
// This function is implemented by walking the directory tree, starting at
// "baseDir", using the Openat syscall with the O_NOFOLLOW flag.
// Symlinks that are part of the "baseDir" path are followed.
// Retries on EINTR.
func OpenDirNofollow(baseDir string, relPath string) (fd int, err error) {
	if !filepath.IsAbs(baseDir) {
		tlog.Warn.Printf("BUG: OpenDirNofollow called with relative baseDir=%q", baseDir)
		return -1, syscall.EINVAL
	}
	if filepath.IsAbs(relPath) {
		tlog.Warn.Printf("BUG: OpenDirNofollow called with absolute relPath=%q", relPath)
		return -1, syscall.EINVAL
	}
	// Open the base dir (following symlinks)
	dirfd, err := retryEINTR2(func() (int, error) {
		return syscall.Open(baseDir, syscall.O_DIRECTORY|O_PATH, 0)
	})
	if err != nil {
		return -1, err
	}
	// Caller wanted to open baseDir itself?
	if relPath == "" {
		return dirfd, nil
	}
	// Split the path into components
	parts := strings.Split(relPath, "/")
	// Walk the directory tree
	var dirfd2 int
	for _, name := range parts {
		dirfd2, err = Openat(dirfd, name, syscall.O_NOFOLLOW|syscall.O_DIRECTORY|O_PATH, 0)
		syscall.Close(dirfd)
		if err != nil {
			return -1, err
		}
		dirfd = dirfd2
	}
	// Return fd to final directory
	return dirfd, nil
}
