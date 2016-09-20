// +build !go1.5
// = go 1.4 or lower

package cryptocore

import (
	"testing"
)

// Native Go crypto with 128-bit IVs is only supported on Go 1.5 and up,
// this should panic.
func TestCryptoCoreNewGo14(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	key := make([]byte, 32)
	New(key, BackendGoGCM, 128)
}
