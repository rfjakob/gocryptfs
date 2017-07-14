// +build !without_openssl

// We compare against Go's built-in GCM implementation. Since stupidgcm only
// supports 128-bit IVs and Go only supports that from 1.5 onward, we cannot
// run these tests on older Go versions.
package stupidgcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
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
// GCM implemenatation and verifies that the results are identical.
func TestEncryptDecrypt(t *testing.T) {
	key := randBytes(32)
	sGCM := New(key, false)
	authData := randBytes(24)
	iv := randBytes(16)
	dst := make([]byte, 71) // 71 = random length

	gAES, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		t.Fatal(err)
	}

	// Check all block sizes from 1 to 5000
	for i := 1; i < 5000; i++ {
		in := make([]byte, i)

		sOut := sGCM.Seal(dst, iv, in, authData)
		gOut := gGCM.Seal(dst, iv, in, authData)

		// Ciphertext must be identical to Go GCM
		if !bytes.Equal(sOut, gOut) {
			t.Fatalf("Compare failed for encryption, size %d", i)
			t.Log("sOut:")
			t.Log("\n" + hex.Dump(sOut))
			t.Log("gOut:")
			t.Log("\n" + hex.Dump(gOut))
		}

		sOut2, sErr := sGCM.Open(dst, iv, sOut[len(dst):], authData)
		if sErr != nil {
			t.Fatal(sErr)
		}
		gOut2, gErr := gGCM.Open(dst, iv, gOut[len(dst):], authData)
		if gErr != nil {
			t.Fatal(gErr)
		}

		// Plaintext must be identical to Go GCM
		if !bytes.Equal(sOut2, gOut2) {
			t.Fatalf("Compare failed for decryption, size %d", i)
		}
	}
}

// Seal re-uses the "dst" buffer it is large enough.
// Check that this works correctly by testing different "dst" capacities from
// 5000 to 16 and "in" lengths from 1 to 5000.
func TestInplaceSeal(t *testing.T) {
	key := randBytes(32)
	sGCM := New(key, false)
	authData := randBytes(24)
	iv := randBytes(16)

	gAES, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		t.Fatal(err)
	}
	max := 5016
	// Check all block sizes from 1 to 5000
	for i := 1; i < max-16; i++ {
		in := make([]byte, i)
		dst := make([]byte, max-i)
		dst = dst[:16]

		sOut := sGCM.Seal(dst, iv, in, authData)
		dst2 := make([]byte, 16)
		gOut := gGCM.Seal(dst2, iv, in, authData)

		// Ciphertext must be identical to Go GCM
		if !bytes.Equal(sOut, gOut) {
			t.Fatalf("Compare failed for encryption, size %d", i)
			t.Log("sOut:")
			t.Log("\n" + hex.Dump(sOut))
			t.Log("gOut:")
			t.Log("\n" + hex.Dump(gOut))
		}
	}
}

// Open re-uses the "dst" buffer it is large enough.
// Check that this works correctly by testing different "dst" capacities from
// 5000 to 16 and "in" lengths from 1 to 5000.
func TestInplaceOpen(t *testing.T) {
	key := randBytes(32)
	sGCM := New(key, false)
	authData := randBytes(24)
	iv := randBytes(16)

	gAES, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		t.Fatal(err)
	}
	max := 5016
	// Check all block sizes from 1 to 5000
	for i := 1; i < max-16; i++ {
		in := make([]byte, i)

		gCiphertext := gGCM.Seal(iv, iv, in, authData)

		dst := make([]byte, max-i)
		// sPlaintext ... stupidgcm plaintext
		sPlaintext, err := sGCM.Open(dst[:0], iv, gCiphertext[16:], authData)
		if err != nil {
			t.Fatal(err)
		}

		// Plaintext must be identical to Go GCM
		if !bytes.Equal(in, sPlaintext) {
			t.Fatalf("Compare failed, i=%d", i)
		}
	}
}

// TestCorruption verifies that changes in the ciphertext result in a decryption
// error
func TestCorruption(t *testing.T) {
	key := randBytes(32)
	sGCM := New(key, false)
	authData := randBytes(24)
	iv := randBytes(16)

	in := make([]byte, 354)
	sOut := sGCM.Seal(nil, iv, in, authData)
	sOut2, sErr := sGCM.Open(nil, iv, sOut, authData)
	if sErr != nil {
		t.Fatal(sErr)
	}
	if !bytes.Equal(in, sOut2) {
		t.Fatalf("Compare failed")
	}

	// Corrupt first byte
	sOut[0]++
	sOut2, sErr = sGCM.Open(nil, iv, sOut, authData)
	if sErr == nil || sOut2 != nil {
		t.Fatalf("Should have gotten error")
	}
	sOut[0]--

	// Corrupt last byte
	sOut[len(sOut)-1]++
	sOut2, sErr = sGCM.Open(nil, iv, sOut, authData)
	if sErr == nil || sOut2 != nil {
		t.Fatalf("Should have gotten error")
	}
	sOut[len(sOut)-1]--

	// Append one byte
	sOut = append(sOut, 0)
	sOut2, sErr = sGCM.Open(nil, iv, sOut, authData)
	if sErr == nil || sOut2 != nil {
		t.Fatalf("Should have gotten error")
	}
}
