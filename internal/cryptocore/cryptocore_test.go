package cryptocore

import (
	"testing"
)

// "New" should accept all param combinations
func TestCryptoCoreNew(t *testing.T) {
	key := make([]byte, 32)

	c := New(key, true, true)
	if c.IVLen != 16 {
		t.Fail()
	}
	c = New(key, true, false)
	if c.IVLen != 12 {
		t.Fail()
	}
	c = New(key, false, false)
	if c.IVLen != 12 {
		t.Fail()
	}
	// "New(key, false, true)" is tested for Go 1.4 and 1.5+ seperately
}

// "New" should panic on any key not 32 bytes long
func TestNewPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	key := make([]byte, 16)
	New(key, true, true)
}
