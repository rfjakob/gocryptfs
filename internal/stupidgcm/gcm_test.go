// +build !without_openssl

// We compare against Go's built-in GCM implementation. Since stupidgcm only
// supports 128-bit IVs and Go only supports that from 1.5 onward, we cannot
// run these tests on older Go versions.
package stupidgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestStupidGCM(t *testing.T) {
	key := randBytes(32)
	sGCM := NewAES256GCM(key)

	gAES, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		t.Fatal(err)
	}

	testCiphers(t, sGCM, gGCM)
}
