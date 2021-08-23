// Package siv_aead wraps the functions provided by siv
// in a crypto.AEAD interface.
package siv_aead

import (
	"crypto/cipher"
	"log"

	"github.com/jacobsa/crypto/siv"
)

type sivAead struct {
	key []byte
}

var _ cipher.AEAD = &sivAead{}

const (
	// KeyLen is the required key length. The SIV algorithm supports other lengths,
	// but we only support 64.
	KeyLen = 64
	// NonceSize is the required nonce/IV length.
	// SIV supports any nonce size, but in gocryptfs we exclusively use 16.
	NonceSize = 16
	// Overhead is the number of bytes added for integrity checking
	Overhead = 16
)

// New returns a new cipher.AEAD implementation.
func New(key []byte) cipher.AEAD {
	if len(key) != KeyLen {
		// SIV supports 32, 48 or 64-byte keys, but in gocryptfs we
		// exclusively use 64.
		log.Panicf("Key must be %d byte long (you passed %d)", KeyLen, len(key))
	}
	return new2(key)
}

// Same as "New" without the 64-byte restriction.
func new2(keyIn []byte) cipher.AEAD {
	// Create a private copy so the caller can zero the one he owns
	key := append([]byte{}, keyIn...)
	return &sivAead{
		key: key,
	}
}

func (s *sivAead) NonceSize() int {
	// SIV supports any nonce size, but in gocryptfs we exclusively use 16.
	return NonceSize
}

func (s *sivAead) Overhead() int {
	return Overhead
}

// Seal encrypts "in" using "nonce" and "authData" and appends the result to "dst"
func (s *sivAead) Seal(dst, nonce, plaintext, authData []byte) []byte {
	if len(nonce) != 16 {
		// SIV supports any nonce size, but in gocryptfs we exclusively use 16.
		log.Panic("nonce must be 16 bytes long")
	}
	if len(s.key) == 0 {
		log.Panic("Key has been wiped?")
	}
	// https://github.com/jacobsa/crypto/blob/master/siv/encrypt.go#L48:
	// As per RFC 5297 section 3, you may use this function for nonce-based
	// authenticated encryption by passing a nonce as the last associated
	// data element.
	associated := [][]byte{authData, nonce}
	out, err := siv.Encrypt(dst, s.key, plaintext, associated)
	if err != nil {
		log.Panic(err)
	}
	return out
}

// Open decrypts "in" using "nonce" and "authData" and appends the result to "dst"
func (s *sivAead) Open(dst, nonce, ciphertext, authData []byte) ([]byte, error) {
	if len(nonce) != 16 {
		// SIV supports any nonce size, but in gocryptfs we exclusively use 16.
		log.Panic("nonce must be 16 bytes long")
	}
	if len(s.key) == 0 {
		log.Panic("Key has been wiped?")
	}
	associated := [][]byte{authData, nonce}
	dec, err := siv.Decrypt(s.key, ciphertext, associated)
	return append(dst, dec...), err
}

// Wipe tries to wipe the AES key from memory by overwriting it with zeros
// and setting the reference to nil.
//
// This is not bulletproof due to possible GC copies, but
// still raises to bar for extracting the key.
func (s *sivAead) Wipe() {
	for i := range s.key {
		s.key[i] = 0
	}
	s.key = nil
}
