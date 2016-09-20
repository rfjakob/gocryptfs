// +build go1.5
// = go 1.5 or higher

package cryptocore

import (
	"testing"
)

func TestCryptoCoreNewGo15(t *testing.T) {
	key := make([]byte, 32)
	c := New(key, BackendGoGCM, 128)
	if c.IVLen != 16 {
		t.Fail()
	}
}
