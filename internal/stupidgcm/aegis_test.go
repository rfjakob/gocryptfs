//go:build !without_aegis && cgo
// +build !without_aegis,cgo

package stupidgcm

import "testing"

func TestStupidAegis(t *testing.T) {
	if BuiltWithoutAegis {
		t.Skip("Aegis support has been disabled at compile-time")
	}
	key := randBytes(16)
	c := NewAegis(key)

	testCiphers(t, c, c)
}
