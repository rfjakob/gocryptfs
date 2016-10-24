package cryptocore

import (
	"testing"
)

// "New" should accept at least these param combinations
func TestCryptoCoreNew(t *testing.T) {
	key := make([]byte, 32)

	c := New(key, BackendOpenSSL, 128)
	if c.IVLen != 16 {
		t.Fail()
	}
	c = New(key, BackendGoGCM, 96)
	if c.IVLen != 12 {
		t.Fail()
	}
	// "New(key, BackendGoGCM, 128)" is tested for Go 1.4 and 1.5+ separately
}

// "New" should panic on any key not 32 bytes long
func TestNewPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	key := make([]byte, 16)
	New(key, BackendOpenSSL, 128)
}
