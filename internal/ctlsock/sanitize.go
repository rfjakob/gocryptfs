package ctlsock

import (
	"path/filepath"
)

// SanitizePath adapts filepath.Clean for FUSE paths.
// 1) It always returns a relative path
// 2) It returns "" instead of "."
// See the TestSanitizePath testcases for examples.
func SanitizePath(path string) string {
	clean := filepath.Clean(path)
	if clean == "." || clean == "/" {
		return ""
	}
	if clean[0] == '/' {
		clean = clean[1:]
	}
	return clean
}
