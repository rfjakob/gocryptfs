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

func NewChacha20poly1305(key []byte) *stupidChacha20poly1305 {
	if len(key) != chacha20poly1305.KeySize {
		log.Panicf("Only %d-byte keys are supported, you passed %d bytes", chacha20poly1305.KeySize, len(key))
	}
	return &stupidChacha20poly1305{
		stupidAEADCommon{
			key:              append([]byte{}, key...), // private copy
			openSSLEVPCipher: C.EVP_chacha20_poly1305(),
			nonceSize:        chacha20poly1305.NonceSize,
		},
	}
}
