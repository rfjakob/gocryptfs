package cryptfs

import (
	"bytes"
	"testing"
)

func TestTranslatePath(t *testing.T) {
	var s []string
	s = append(s, "foo")
	s = append(s, "foo12312312312312312313123123123")
	s = append(s, "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890")

	key := make([]byte, KEY_LEN)
	fs := NewCryptFS(key, true)

	for _, n := range s {
		c := fs.EncryptPath(n)
		d, err := fs.DecryptPath(c)
		if err != nil {
			t.Errorf("Got error from DecryptName: %s", err)
		}
		if d != n {
			t.Errorf("Content mismatch, n=\"%s\" d=\"%s\"", n, d)
		}
		//fmt.Printf("n=%s c=%s d=%s\n", n, c, d)
	}
}

func TestPad16(t *testing.T) {
	var s [][]byte
	s = append(s, []byte("foo"))
	s = append(s, []byte("12345678901234567"))
	s = append(s, []byte("12345678901234567abcdefg"))

	key := make([]byte, KEY_LEN)
	fs := NewCryptFS(key, true)

	for i := range s {
		orig := s[i]
		padded := fs.pad16(orig)
		if len(padded) <= len(orig) {
			t.Errorf("Padded length not bigger than orig: %d", len(padded))
		}
		if len(padded)%16 != 0 {
			t.Errorf("Length is not aligend: %d", len(padded))
		}
		unpadded, err := fs.unPad16(padded)
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
