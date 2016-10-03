// Package siv_aead wraps the functions provided by siv
// in a crypto.AEAD interface.
package siv_aead

import (
	"crypto/cipher"

	"github.com/jacobsa/crypto/siv"
)

type sivAead struct {
	key []byte
}

var _ cipher.AEAD = &sivAead{}

// New returns a new cipher.AEAD implementation.
func New(key []byte) cipher.AEAD {
	return &sivAead{
		key: key,
	}
}

func (s *sivAead) NonceSize() int {
	// SIV supports any nonce size, but in gocryptfs we exclusively use 16.
	return 16
}

func (s *sivAead) Overhead() int {
	return 16
}

// Seal encrypts "in" using "nonce" and "authData" and append the result to "dst"
func (s *sivAead) Seal(dst, nonce, plaintext, authData []byte) []byte {
	if len(nonce) != 16 {
		// SIV supports any nonce size, but in gocryptfs we exclusively use 16.
		panic("nonce must be 16 bytes long")
	}
	// https://github.com/jacobsa/crypto/blob/master/siv/encrypt.go#L48:
	// As per RFC 5297 section 3, you may use this function for nonce-based
	// authenticated encryption by passing a nonce as the last associated
	// data element.
	associated := [][]byte{authData, nonce}
	out, err := siv.Encrypt(dst, s.key, plaintext, associated)
	if err != nil {
		panic(err)
	}
	return out
}

// Open decrypts "in" using "nonce" and "authData" and append the result to "dst"
func (s *sivAead) Open(dst, nonce, ciphertext, authData []byte) ([]byte, error) {
	if len(nonce) != 16 {
		// SIV supports any nonce size, but in gocryptfs we exclusively use 16.
		panic("nonce must be 16 bytes long")
	}
	associated := [][]byte{authData, nonce}
	dec, err := siv.Decrypt(s.key, ciphertext, associated)
	return append(dst, dec...), err
}
