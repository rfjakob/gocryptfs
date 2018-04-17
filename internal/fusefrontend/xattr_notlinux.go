// +build !linux

// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

func disallowedXAttrName(attr string) bool {
	return false
}
