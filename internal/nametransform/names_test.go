package nametransform

import (
	"bytes"
	"testing"
)

func TestPad16(t *testing.T) {
	var s [][]byte
	s = append(s, []byte("foo"))
	s = append(s, []byte("12345678901234567"))
	s = append(s, []byte("12345678901234567abcdefg"))

	for i := range s {
		orig := s[i]
		padded := pad16(orig)
		if len(padded) <= len(orig) {
			t.Errorf("Padded length not bigger than orig: %d", len(padded))
		}
		if len(padded)%16 != 0 {
			t.Errorf("Length is not aligend: %d", len(padded))
		}
		unpadded, err := unPad16(padded)
		if err != nil {
			t.Error("unPad16 returned error:", err)
		}
		if len(unpadded) != len(orig) {
			t.Errorf("Size mismatch: orig=%d unpadded=%d", len(s[i]), len(unpadded))
		}
		if !bytes.Equal(orig, unpadded) {
			t.Error("Content mismatch orig vs unpadded")
		}
	}
}
