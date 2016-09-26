// Package siv_aead wraps the functions provided by siv
// in a crypto.AEAD interface.
package siv_aead

import (
	"github.com/jacobsa/crypto/siv"
)

type sivAead struct {
	key []byte
}

func New(key []byte) *sivAead {
	return &sivAead{
		key: key,
	}
}

func (s *sivAead) NonceSize() int {
	// SIV supports any nonce size, but in gocryptfs we exclusively use 16.
	return 16
}

func (s *sivAead) Overhead() int {
	// RFC5297:
	// [...] the key length used by AES in CTR and S2V is len(K)/2 and will
	// each be either 128 bits, 192 bits, or 256 bits.
	return len(s.key) / 2

}

// Seal - encrypt "in" using "nonce" and "authData" and append the result to "dst"
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

// Open - decrypt "in" using "nonce" and "authData" and append the result to "dst"
func (s *sivAead) Open(dst, nonce, ciphertext, authData []byte) ([]byte, error) {
	if len(nonce) != 16 {
		// SIV supports any nonce size, but in gocryptfs we exclusively use 16.
		panic("nonce must be 16 bytes long")
	}
	associated := [][]byte{authData, nonce}
	dec, err := siv.Decrypt(s.key, ciphertext, associated)
	return append(dst, dec...), err
}
