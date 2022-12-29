package ctlsocksrv

import (
	"path/filepath"
	"strings"
)

// SanitizePath adapts filepath.Clean for FUSE paths.
//  1. Leading slash(es) are dropped
//  2. It returns "" instead of "."
//  3. If the cleaned path points above CWD (start with ".."), an empty string
//     is returned
//
// See the TestSanitizePath testcases for examples.
func SanitizePath(path string) string {
	// (1)
	for len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	if len(path) == 0 {
		return ""
	}
	clean := filepath.Clean(path)
	// (2)
	if clean == "." {
		return ""
	}
	// (3)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	return clean
}
