// +build go1.5
// = go 1.5 or higher

package cryptocore

import (
	"testing"
)

// Native Go crypto with 128-bit IVs is only supported on Go 1.5 and up
func TestCryptoCoreNewGo15(t *testing.T) {
	key := make([]byte, 32)
	c := New(key, false, true)
	if c.IVLen != 12 {
		t.Fail()
	}
}
