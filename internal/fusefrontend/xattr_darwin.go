// +build darwin

// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

import "github.com/pkg/xattr"

func disallowedXAttrName(attr string) bool {
	return false
}

// On Darwin it is needed to unset XATTR_NOSECURITY 0x0008
func filterXattrSetFlags(flags int) int {
	return flags &^ xattr.XATTR_NOSECURITY
}
