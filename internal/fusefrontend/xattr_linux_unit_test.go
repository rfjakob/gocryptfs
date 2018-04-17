// +build linux

package fusefrontend

import (
	"testing"
)

func TestDisallowedLinuxAttributes(t *testing.T) {
	if !disallowedXAttrName("xxxx") {
		t.Fatalf("Names that don't start with 'user.' should fail")
	}
}
