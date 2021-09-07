// +build !without_openssl

package stupidgcm

import (
	"log"
)

/*
#include <openssl/evp.h>
*/
import "C"

type stupidAEADCommon struct {
	wiped            bool
	key              []byte
	openSSLEVPCipher *C.EVP_CIPHER
	nonceSize        int
}

// Overhead returns the number of bytes that are added for authentication.
//
// Part of the cipher.AEAD interface.
func (c *stupidAEADCommon) Overhead() int {
	return tagLen
}

// NonceSize returns the required size of the nonce / IV
//
// Part of the cipher.AEAD interface.
func (c *stupidAEADCommon) NonceSize() int {
	return c.nonceSize
}

// Seal encrypts "in" using "iv" and "authData" and append the result to "dst"
//
// Part of the cipher.AEAD interface.
func (c *stupidAEADCommon) Seal(dst, iv, in, authData []byte) []byte {
	return openSSLSeal(c, dst, iv, in, authData)
}

// Open decrypts "in" using "iv" and "authData" and append the result to "dst"
//
// Part of the cipher.AEAD interface.
func (c *stupidAEADCommon) Open(dst, iv, in, authData []byte) ([]byte, error) {
	return openSSLOpen(c, dst, iv, in, authData)
}

// Wipe tries to wipe the key from memory by overwriting it with zeros.
//
// This is not bulletproof due to possible GC copies, but
// still raises the bar for extracting the key.
func (c *stupidAEADCommon) Wipe() {
	key := c.key
	c.wiped = true
	c.key = nil
	for i := range key {
		key[i] = 0
	}
}

func (c *stupidAEADCommon) Wiped() bool {
	if c.wiped {
		return true
	}
	if len(c.key) != keyLen {
		log.Panicf("wrong key length %d", len(c.key))
	}
	return false
}
