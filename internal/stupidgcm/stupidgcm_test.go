// +build !without_openssl

// We compare against Go's built-in GCM implementation. Since stupidgcm only
// supports 128-bit IVs and Go only supports that from 1.5 onward, we cannot
// run these tests on older Go versions.
package stupidgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"log"
	"testing"
)

// Get "n" random bytes from /dev/urandom or panic
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

// TestEncryptDecrypt encrypts and decrypts using both stupidgcm and Go's built-in
// GCM implementation and verifies that the results are identical.
func TestEncryptDecrypt(t *testing.T) {
	key := randBytes(32)
	sGCM := New(key, false)

	gAES, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		t.Fatal(err)
	}

	testEncryptDecrypt(t, sGCM, gGCM)
}

// Seal re-uses the "dst" buffer it is large enough.
// Check that this works correctly by testing different "dst" capacities from
// 5000 to 16 and "in" lengths from 1 to 5000.
func TestInplaceSeal(t *testing.T) {
	key := randBytes(32)
	sGCM := New(key, false)

	gAES, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		t.Fatal(err)
	}

	testInplaceSeal(t, sGCM, gGCM)
}

// Open re-uses the "dst" buffer it is large enough.
// Check that this works correctly by testing different "dst" capacities from
// 5000 to 16 and "in" lengths from 1 to 5000.
func TestInplaceOpen(t *testing.T) {
	key := randBytes(32)
	sGCM := New(key, false)

	gAES, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		t.Fatal(err)
	}

	testInplaceOpen(t, sGCM, gGCM)
}

// TestCorruption verifies that changes in the ciphertext result in a decryption
// error
func TestCorruption(t *testing.T) {
	key := randBytes(32)
	sGCM := New(key, false)

	testCorruption(t, sGCM)
}
