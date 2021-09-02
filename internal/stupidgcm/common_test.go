package stupidgcm

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"log"
	"testing"
)

func testCiphers(t *testing.T, our cipher.AEAD, ref cipher.AEAD) {
	t.Run("testEncryptDecrypt", func(t *testing.T) { testEncryptDecrypt(t, our, ref) })
	t.Run("testInplaceSeal", func(t *testing.T) { testInplaceSeal(t, our, ref) })
	t.Run("testInplaceOpen", func(t *testing.T) { testInplaceOpen(t, our, ref) })
	t.Run("testCorruption_c1", func(t *testing.T) { testCorruption(t, our) })
	t.Run("testCorruption_c2", func(t *testing.T) { testCorruption(t, ref) })
	t.Run("testWipe", func(t *testing.T) { testWipe(t, our) })
}

// testEncryptDecrypt encrypts and decrypts using both stupidgcm and Go's built-in
// GCM implementation and verifies that the results are identical.
func testEncryptDecrypt(t *testing.T, c1 cipher.AEAD, c2 cipher.AEAD) {
	if c1.NonceSize() != c2.NonceSize() {
		t.Fatal("different NonceSize")
	}
	if c1.Overhead() != c2.Overhead() {
		t.Fatal("different Overhead")
	}

	authData := randBytes(24)
	iv := randBytes(c1.NonceSize())

	dst := make([]byte, 71) // 71 = arbitrary length

	// Check all block sizes from 1 to 5000
	for i := 1; i < 5000; i++ {
		in := make([]byte, i)

		c1out := c1.Seal(dst, iv, in, authData)
		c2out := c2.Seal(dst, iv, in, authData)

		// Ciphertext must be identical to Go GCM
		if !bytes.Equal(c1out, c2out) {
			t.Fatalf("Compare failed for encryption, size %d", i)
			t.Log("c1out:")
			t.Log("\n" + hex.Dump(c1out))
			t.Log("c2out:")
			t.Log("\n" + hex.Dump(c2out))
		}

		c1out2, sErr := c1.Open(dst, iv, c1out[len(dst):], authData)
		if sErr != nil {
			t.Fatal(sErr)
		}
		c2out2, gErr := c2.Open(dst, iv, c2out[len(dst):], authData)
		if gErr != nil {
			t.Fatal(gErr)
		}

		// Plaintext must be identical to Go GCM
		if !bytes.Equal(c1out2, c2out2) {
			t.Fatalf("Compare failed for decryption, size %d", i)
		}
	}
}

// Seal re-uses the "dst" buffer it is large enough.
// Check that this works correctly by testing different "dst" capacities from
// 5000 to 16 and "in" lengths from 1 to 5000.
func testInplaceSeal(t *testing.T, c1 cipher.AEAD, c2 cipher.AEAD) {
	authData := randBytes(24)
	iv := randBytes(c1.NonceSize())

	max := 5016
	// Check all block sizes from 1 to 5000
	for i := 1; i < max-16; i++ {
		in := make([]byte, i)
		dst := make([]byte, max-i)
		dst = dst[:16]

		c1out := c1.Seal(dst, iv, in, authData)
		dst2 := make([]byte, 16)
		c2out := c2.Seal(dst2, iv, in, authData)

		// Ciphertext must be identical to Go GCM
		if !bytes.Equal(c1out, c2out) {
			t.Fatalf("Compare failed for encryption, size %d", i)
			t.Log("sOut:")
			t.Log("\n" + hex.Dump(c1out))
			t.Log("gOut:")
			t.Log("\n" + hex.Dump(c2out))
		}
	}
}

// testInplaceOpen - Open re-uses the "dst" buffer it is large enough.
// Check that this works correctly by testing different "dst" capacities from
// 5000 to 16 and "in" lengths from 1 to 5000.
func testInplaceOpen(t *testing.T, c1 cipher.AEAD, c2 cipher.AEAD) {
	authData := randBytes(24)
	iv := randBytes(c1.NonceSize())

	max := 5016
	// Check all block sizes from 1 to 5000
	for i := 1; i < max-c1.NonceSize(); i++ {
		in := make([]byte, i)

		c2ciphertext := c2.Seal(iv, iv, in, authData)

		dst := make([]byte, max-i)
		// sPlaintext ... stupidgcm plaintext
		c1plaintext, err := c1.Open(dst[:0], iv, c2ciphertext[c1.NonceSize():], authData)
		if err != nil {
			t.Fatal(err)
		}

		// Plaintext must be identical to Go GCM
		if !bytes.Equal(in, c1plaintext) {
			t.Fatalf("Compare failed, i=%d", i)
		}
	}
}

// testCorruption verifies that changes in the ciphertext result in a decryption
// error
func testCorruption(t *testing.T, c cipher.AEAD) {
	authData := randBytes(24)
	iv := randBytes(c.NonceSize())

	in := make([]byte, 354)
	out := c.Seal(nil, iv, in, authData)
	out2, sErr := c.Open(nil, iv, out, authData)
	if sErr != nil {
		t.Fatal(sErr)
	}
	if !bytes.Equal(in, out2) {
		t.Fatalf("Compare failed")
	}

	// Corrupt first byte
	out[0]++
	out2, sErr = c.Open(nil, iv, out, authData)
	if sErr == nil || out2 != nil {
		t.Fatalf("Should have gotten error")
	}
	out[0]--

	// Corrupt last byte
	out[len(out)-1]++
	out2, sErr = c.Open(nil, iv, out, authData)
	if sErr == nil || out2 != nil {
		t.Fatalf("Should have gotten error")
	}
	out[len(out)-1]--

	// Append one byte
	out = append(out, 0)
	out2, sErr = c.Open(nil, iv, out, authData)
	if sErr == nil || out2 != nil {
		t.Fatalf("Should have gotten error")
	}
}

type Wiper interface {
	Wipe()
}

func testWipe(t *testing.T, c cipher.AEAD) {
	var key []byte
	switch c2 := c.(type) {
	case *StupidGCM:
		c2.Wipe()
		key = c2.key
	case *stupidChacha20poly1305:
		c2.Wipe()
		key = c2.key
	default:
		t.Fatalf("BUG: unhandled type %t", c2)
	}
	if key != nil {
		t.Fatal("key is not nil")
	}
}

// Get "n" random bytes from /dev/urandom or panic
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Panic("Failed to read random bytes: " + err.Error())
	}
	return b
}
