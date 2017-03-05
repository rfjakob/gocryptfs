package siv_aead

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jacobsa/crypto/siv"
)

// Test all supported key lengths
func TestKeyLens(t *testing.T) {
	keyLens := []int{32, 48, 64}
	nonce := make([]byte, 16)
	plaintext := []byte("foobar")
	for _, keyLen := range keyLens {
		key := make([]byte, keyLen)
		a := new2(key)
		ciphertext2 := a.Seal(nil, nonce, plaintext, nil)

		ciphertext, err := siv.Encrypt(nil, key, plaintext, [][]byte{nil, nonce})
		if err != nil {
			t.Error(err)
		} else if o := len(ciphertext) - len(plaintext); o != a.Overhead() {
			t.Errorf("keyLen=%d, actual overhead: %d\n", keyLen, o)
		}
		if !bytes.Equal(ciphertext, ciphertext2) {
			t.Errorf("siv and siv_aead produce different results")
		}
	}

}

// Test using a 32-byte key
func TestK32(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	nonce := bytes.Repeat([]byte{2}, 16)
	plaintext := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	aData := make([]byte, 24)
	// Compare siv and siv_aead results
	sResult, err := siv.Encrypt(nonce, key, plaintext, [][]byte{aData, nonce})
	if err != nil {
		t.Fatal(err)
	}
	a := new2(key)
	aResult := a.Seal(nonce, nonce, plaintext, aData)
	if !bytes.Equal(sResult, aResult) {
		t.Errorf("siv and siv_aead produce different results")
	}
	expectedResult, _ := hex.DecodeString(
		"02020202020202020202020202020202ad7a4010649a84d8c1dd5f752e935eed57d45b8b10008f3834")
	if !bytes.Equal(aResult, expectedResult) {
		t.Errorf(hex.EncodeToString(aResult))
	}
	// Verify overhead
	overhead := len(aResult) - len(plaintext) - len(nonce)
	if overhead != a.Overhead() {
		t.Errorf("Overhead() returns a wrong value")
	}
	// Decrypt
	p1, err := a.Open(nil, aResult[:16], aResult[16:], aData)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(plaintext, p1) {
		t.Errorf("wrong plaintext")
	}
	// Decrypt and append
	dst := []byte{0xaa, 0xbb, 0xcc}
	p2, err := a.Open(dst, aResult[:16], aResult[16:], aData)
	if err != nil {
		t.Error(err)
	}
	p2e := append(dst, plaintext...)
	if !bytes.Equal(p2e, p2) {
		t.Errorf("wrong plaintext: %s", hex.EncodeToString(p2))
	}
	// Decrypt corrupt
	aResult[17] = 0
	_, err = a.Open(nil, aResult[:16], aResult[16:], aData)
	if err == nil {
		t.Error("should have failed")
	}
	// Decrypt and append corrupt
	aResult[17] = 0
	_, err = a.Open(dst, aResult[:16], aResult[16:], aData)
	if err == nil {
		t.Error("should have failed")
	}
}

// Test using a 64-byte key
func TestK64(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 64)
	nonce := bytes.Repeat([]byte{2}, 16)
	plaintext := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	aData := make([]byte, 24)
	// Compare siv and siv_aead results
	sResult, err := siv.Encrypt(nonce, key, plaintext, [][]byte{aData, nonce})
	if err != nil {
		t.Fatal(err)
	}
	a := New(key)
	aResult := a.Seal(nonce, nonce, plaintext, aData)
	if !bytes.Equal(sResult, aResult) {
		t.Errorf("siv and siv_aead produce different results")
	}
	expectedResult, _ := hex.DecodeString(
		"02020202020202020202020202020202317b316f67c3ad336c01c9a01b4c5e552ba89e966bc4c1ade1")
	if !bytes.Equal(aResult, expectedResult) {
		t.Errorf(hex.EncodeToString(aResult))
	}
	// Verify overhead
	overhead := len(aResult) - len(plaintext) - len(nonce)
	if overhead != a.Overhead() {
		t.Errorf("Overhead() returns a wrong value")
	}
	// Decrypt
	p1, err := a.Open(nil, aResult[:16], aResult[16:], aData)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(plaintext, p1) {
		t.Errorf("wrong plaintext")
	}
	// Decrypt and append
	dst := []byte{0xaa, 0xbb, 0xcc}
	p2, err := a.Open(dst, aResult[:16], aResult[16:], aData)
	if err != nil {
		t.Error(err)
	}
	p2e := append(dst, plaintext...)
	if !bytes.Equal(p2e, p2) {
		t.Errorf("wrong plaintext: %s", hex.EncodeToString(p2))
	}
	// Decrypt corrupt
	aResult[17] = 0
	_, err = a.Open(nil, aResult[:16], aResult[16:], aData)
	if err == nil {
		t.Error("should have failed")
	}
	// Decrypt and append corrupt
	aResult[17] = 0
	_, err = a.Open(dst, aResult[:16], aResult[16:], aData)
	if err == nil {
		t.Error("should have failed")
	}
}
