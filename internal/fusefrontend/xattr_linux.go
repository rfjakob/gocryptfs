// +build linux

// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

import (
	"strings"
)

// Only allow the "user" namespace, block "trusted" and "security", as
// these may be interpreted by the system, and we don't want to cause
// trouble with our encrypted garbage.
const xattrUserPrefix = "user."

func disallowedXAttrName(attr string) bool {
	return !strings.HasPrefix(attr, xattrUserPrefix)
}

func filterXattrSetFlags(flags int) int {
	return flags
}
