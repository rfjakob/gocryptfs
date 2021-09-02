// +build !without_openssl

// We compare against Go's built-in GCM implementation. Since stupidgcm only
// supports 128-bit IVs and Go only supports that from 1.5 onward, we cannot
// run these tests on older Go versions.
package stupidgcm

import (
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestEncryptDecrypt encrypts and decrypts using both stupidgcm and Go's built-in
// GCM implementation and verifies that the results are identical.
func TestEncryptDecryptChacha(t *testing.T) {
	key := randBytes(32)
	c := newChacha20poly1305(key)
	ref, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}

	testEncryptDecrypt(t, c, ref)
}

// Seal re-uses the "dst" buffer it is large enough.
// Check that this works correctly by testing different "dst" capacities from
// 5000 to 16 and "in" lengths from 1 to 5000.
func TestInplaceSealChacha(t *testing.T) {
	key := randBytes(32)
	c := newChacha20poly1305(key)
	ref, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}

	testInplaceSeal(t, c, ref)
}

// Open re-uses the "dst" buffer it is large enough.
// Check that this works correctly by testing different "dst" capacities from
// 5000 to 16 and "in" lengths from 1 to 5000.
func TestInplaceOpenChacha(t *testing.T) {
	key := randBytes(32)
	c := newChacha20poly1305(key)
	ref, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}

	testInplaceOpen(t, c, ref)
}

// TestCorruption verifies that changes in the ciphertext result in a decryption
// error
func TestCorruptionChacha(t *testing.T) {
	key := randBytes(32)
	c := newChacha20poly1305(key)

	testCorruption(t, c)
}
