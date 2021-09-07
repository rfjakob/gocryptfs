// +build !without_openssl

// Package stupidgcm is a thin wrapper for OpenSSL's GCM encryption and
// decryption functions. It only support 32-byte keys and 16-bit IVs.
package stupidgcm

// #include <openssl/evp.h>
import "C"

import (
	"crypto/cipher"
	"log"
)

const (
	// BuiltWithoutOpenssl indicates if openssl been disabled at compile-time
	BuiltWithoutOpenssl = false

	keyLen = 32
	ivLen  = 16
	tagLen = 16
)

type stupidGCM struct {
	stupidAEADCommon
}

// Verify that we satisfy the interface
var _ cipher.AEAD = &stupidGCM{}

// New returns a new cipher.AEAD implementation..
func New(keyIn []byte, forceDecode bool) cipher.AEAD {
	if len(keyIn) != keyLen {
		log.Panicf("Only %d-byte keys are supported", keyLen)
	}
	return &stupidGCM{
		stupidAEADCommon{
			// Create a private copy of the key
			key:              append([]byte{}, keyIn...),
			openSSLEVPCipher: C.EVP_aes_256_gcm(),
			nonceSize:        ivLen,
		},
	}
}
