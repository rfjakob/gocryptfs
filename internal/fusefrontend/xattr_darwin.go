// +build darwin

// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

func disallowedXAttrName(attr string) bool {
	return false
}

// On Darwin it is needed to unset XATTR_NOSECURITY 0x0008
func filterXattrSetFlags(flags int) int {
	// See https://opensource.apple.com/source/xnu/xnu-1504.15.3/bsd/sys/xattr.h.auto.html
	const XATTR_NOSECURITY = 0x0008

	return flags &^ XATTR_NOSECURITY
}
