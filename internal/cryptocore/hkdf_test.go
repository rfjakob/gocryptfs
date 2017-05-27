package cryptocore

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type hkdfTestCase struct {
	masterkey []byte
	info      string
	out       []byte
}

// TestHkdfDerive verifies that we get the expected values from hkdfDerive. They
// must not change because this would change the on-disk format.
func TestHkdfDerive(t *testing.T) {
	master0 := bytes.Repeat([]byte{0x00}, 32)
	master1 := bytes.Repeat([]byte{0x01}, 32)
	out1, _ := hex.DecodeString("9ba3cddd48c6339c6e56ebe85f0281d6e9051be4104176e65cb0f8a6f77ae6b4")
	out2, _ := hex.DecodeString("e8a2499f48700b954f31de732efd04abce822f5c948e7fbc0896607be0d36d12")
	out3, _ := hex.DecodeString("9137f2e67a842484137f3c458f357f204c30d7458f94f432fa989be96854a649")
	out4, _ := hex.DecodeString("0bfa5da7d9724d4753269940d36898e2c0f3717c0fee86ada58b5fd6c08cc26c")

	testCases := []hkdfTestCase{
		{master0, "EME filename encryption", out1},
		{master0, hkdfInfoEMENames, out1},
		{master1, "EME filename encryption", out2},
		{master1, hkdfInfoEMENames, out2},
		{master1, "AES-GCM file content encryption", out3},
		{master1, hkdfInfoGCMContent, out3},
		{master1, "AES-SIV file content encryption", out4},
		{master1, hkdfInfoSIVContent, out4},
	}

	for i, v := range testCases {
		out := hkdfDerive(v.masterkey, v.info, 32)
		if !bytes.Equal(out, v.out) {
			want := hex.EncodeToString(v.out)
			have := hex.EncodeToString(out)
			t.Errorf("testcase %d error:\n"+
				"want=%s\n"+
				"have=%s", i, want, have)
		}
	}
}
