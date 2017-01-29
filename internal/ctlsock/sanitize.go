package ctlsock

import (
	"path/filepath"
	"strings"
)

// SanitizePath adapts filepath.Clean for FUSE paths.
// 1) A leading slash is dropped
// 2) It returns "" instead of "."
// 3) If the cleaned path points above CWD (start with ".."), an empty string
//    is returned
// See the TestSanitizePath testcases for examples.
func SanitizePath(path string) string {
	if len(path) == 0 {
		return ""
	}
	// Drop leading slash
	if path[0] == '/' {
		path = path[1:]
	}
	clean := filepath.Clean(path)
	if clean == "." {
		return ""
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	return clean
}
