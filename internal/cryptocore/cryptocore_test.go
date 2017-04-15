package cryptocore

import (
	"testing"
)

// "New" should accept at least these param combinations
func TestCryptoCoreNew(t *testing.T) {
	key := make([]byte, 32)
	for _, useHKDF := range []bool{true, false} {
		c := New(key, BackendOpenSSL, 128, useHKDF, false)
		if c.IVLen != 16 {
			t.Fail()
		}
		c = New(key, BackendGoGCM, 96, useHKDF, false)
		if c.IVLen != 12 {
			t.Fail()
		}
		c = New(key, BackendGoGCM, 128, useHKDF, false)
		if c.IVLen != 16 {
			t.Fail()
		}
	}
}

// "New" should panic on any key not 32 bytes long
func TestNewPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	key := make([]byte, 16)
	New(key, BackendOpenSSL, 128, true, false)
}
