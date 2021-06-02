package nametransform

import (
	"fmt"
	"strings"
)

// IsValidName checks if `name` is a valid name for a normal file
// (does not contain null bytes or "/" etc...).
func IsValidName(name string) error {
	if name == "" {
		return fmt.Errorf("empty input")
	}
	if len(name) > NameMax {
		return fmt.Errorf("too long")
	}
	// A name can never contain a null byte or "/". Make sure we never return those
	// to the kernel, even when we read a corrupted (or fuzzed) filesystem.
	if strings.Contains(name, "\000") || strings.Contains(name, "/") {
		return fmt.Errorf("contains forbidden bytes")
	}
	// The name should never be "." or "..".
	if name == "." || name == ".." {
		return fmt.Errorf(". and .. are forbidden names")
	}
	return nil
}
