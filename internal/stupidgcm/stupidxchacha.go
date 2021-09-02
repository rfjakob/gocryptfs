// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Copied from
// https://github.com/golang/crypto/blob/32db794688a5a24a23a43f2a984cecd5b3d8da58/chacha20poly1305/xchacha20poly1305.go
// and adapted for stupidgcm by @rfjakob.

package stupidgcm

import (
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type stupidXchacha20poly1305 struct {
	key   [chacha20poly1305.KeySize]byte
	wiped bool
}

// NewXchacha20poly1305 returns a XChaCha20-Poly1305 AEAD that uses the given 256-bit key.
//
// XChaCha20-Poly1305 is a ChaCha20-Poly1305 variant that takes a longer nonce,
// suitable to be generated randomly without risk of collisions. It should be
// preferred when nonce uniqueness cannot be trivially ensured, or whenever
// nonces are randomly generated.
func NewXchacha20poly1305(key []byte) cipher.AEAD {
	if len(key) != chacha20poly1305.KeySize {
		panic("bad key length")
	}
	ret := new(stupidXchacha20poly1305)
	copy(ret.key[:], key)
	return ret
}

func (*stupidXchacha20poly1305) NonceSize() int {
	return chacha20poly1305.NonceSizeX
}

func (*stupidXchacha20poly1305) Overhead() int {
	return 16
}

func (x *stupidXchacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if x.wiped {
		panic("BUG: tried to use wiped key")
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		panic("bad nonce length passed to Seal")
	}

	// XChaCha20-Poly1305 technically supports a 64-bit counter, so there is no
	// size limit. However, since we reuse the ChaCha20-Poly1305 implementation,
	// the second half of the counter is not available. This is unlikely to be
	// an issue because the cipher.AEAD API requires the entire message to be in
	// memory, and the counter overflows at 256 GB.
	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("plaintext too large")
	}

	c := new(stupidChacha20poly1305)
	hKey, _ := chacha20.HChaCha20(x.key[:], nonce[0:16])
	copy(c.key[:], hKey)
	defer c.Wipe()

	// The first 4 bytes of the final nonce are unused counter space.
	cNonce := make([]byte, chacha20poly1305.NonceSize)
	copy(cNonce[4:12], nonce[16:24])

	return c.Seal(dst, cNonce[:], plaintext, additionalData)
}

func (x *stupidXchacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if x.wiped {
		panic("BUG: tried to use wiped key")
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		panic("bad nonce length passed to Open")
	}
	if len(ciphertext) < 16 {
		return nil, errors.New("message too short")
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("ciphertext too large")
	}

	c := new(stupidChacha20poly1305)
	hKey, _ := chacha20.HChaCha20(x.key[:], nonce[0:16])
	copy(c.key[:], hKey)
	defer c.Wipe()

	// The first 4 bytes of the final nonce are unused counter space.
	cNonce := make([]byte, chacha20poly1305.NonceSize)
	copy(cNonce[4:12], nonce[16:24])

	return c.Open(dst, cNonce[:], ciphertext, additionalData)
}

// Wipe tries to wipe the key from memory by overwriting it with zeros.
//
// This is not bulletproof due to possible GC copies, but
// still raises the bar for extracting the key.
func (g *stupidXchacha20poly1305) Wipe() {
	g.wiped = true
	for i := range g.key {
		g.key[i] = 0
	}
}
