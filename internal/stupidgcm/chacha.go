// +build !without_openssl

package stupidgcm

import (
	"crypto/cipher"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
)

/*
#include <openssl/evp.h>
*/
import "C"

type stupidChacha20poly1305 struct {
	stupidAEADCommon
}

// Verify that we satisfy the cipher.AEAD interface
var _ cipher.AEAD = &stupidChacha20poly1305{}

// _EVP_chacha20_poly1305 caches C.EVP_chacha20_poly1305() to avoid the Cgo call
// overhead for each instantiation of NewChacha20poly1305.
var _EVP_chacha20_poly1305 *C.EVP_CIPHER

func init() {
	_EVP_chacha20_poly1305 = C.EVP_chacha20_poly1305()
}

// NewChacha20poly1305 returns a new instance of the OpenSSL ChaCha20-Poly1305 AEAD
// cipher ( https://www.openssl.org/docs/man1.1.1/man3/EVP_chacha20_poly1305.html ).
//
// gocryptfs only uses ChaCha20-Poly1305 as a building block for OpenSSL
// XChaCha20-Poly1305. This function is hot because it gets called once for each
// block by XChaCha20-Poly1305.
//
// Only 32-bytes keys and 12-byte IVs are supported.
func NewChacha20poly1305(key []byte) cipher.AEAD {
	if len(key) != chacha20poly1305.KeySize {
		log.Panicf("Only %d-byte keys are supported, you passed %d bytes", chacha20poly1305.KeySize, len(key))
	}
	// private copy
	key2 := make([]byte, chacha20poly1305.KeySize)
	copy(key2, key)
	return &stupidChacha20poly1305{
		stupidAEADCommon{
			key:              key2,
			openSSLEVPCipher: _EVP_chacha20_poly1305,
			nonceSize:        chacha20poly1305.NonceSize,
		},
	}
}
