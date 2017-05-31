package pathiv

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestBlockIV makes sure we don't change the block iv derivation algorithm "BlockIV()"
// inadvertedly.
func TestBlockIV(t *testing.T) {
	b0 := make([]byte, 16)
	b0x := BlockIV(b0, 0)
	if !bytes.Equal(b0, b0x) {
		t.Errorf("b0x should be equal to b0")
	}
	b27 := BlockIV(b0, 0x27)
	expected, _ := hex.DecodeString("00000000000000000000000000000027")
	if !bytes.Equal(b27, expected) {
		t.Errorf("\nhave=%s\nwant=%s", hex.EncodeToString(b27), hex.EncodeToString(expected))
	}
	bff := bytes.Repeat([]byte{0xff}, 16)
	b28 := BlockIV(bff, 0x28)
	expected, _ = hex.DecodeString("ffffffffffffffff0000000000000027")
	if !bytes.Equal(b28, expected) {
		t.Errorf("\nhave=%s\nwant=%s", hex.EncodeToString(b28), hex.EncodeToString(expected))
	}
}
