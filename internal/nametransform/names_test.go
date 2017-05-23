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

// TestUnpad16Garbage - unPad16 should never crash on corrupt or malicious inputs
func TestUnpad16Garbage(t *testing.T) {
	var testCases [][]byte
	testCases = append(testCases, make([]byte, 0))
	testCases = append(testCases, make([]byte, 16))
	testCases = append(testCases, make([]byte, 1))
	testCases = append(testCases, make([]byte, 17))
	testCases = append(testCases, bytes.Repeat([]byte{16}, 16))
	testCases = append(testCases, bytes.Repeat([]byte{17}, 16))
	for _, v := range testCases {
		_, err := unPad16([]byte(v))
		if err == nil {
			t.Fail()
		}
	}
}
