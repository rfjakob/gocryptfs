// Package cryptocore wraps OpenSSL and Go GCM crypto and provides
// a nonce generator.
package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
)

const (
	KeyLen     = 32 // AES-256
	AuthTagLen = 16
)

type CryptoCore struct {
	BlockCipher cipher.Block
	Gcm         cipher.AEAD
	GcmIVGen    *nonceGenerator
	IVLen       int
}

// "New" returns a new CryptoCore object or panics.
//
// Even though the "GCMIV128" feature flag is now mandatory, we must still
// support 96-bit IVs here because they are used for encrypting the master
// key in gocryptfs.conf.
func New(key []byte, useOpenssl bool, GCMIV128 bool) *CryptoCore {

	if len(key) != KeyLen {
		panic(fmt.Sprintf("Unsupported key length %d", len(key)))
	}

	// We want the IV size in bytes
	IVLen := 96 / 8
	if GCMIV128 {
		IVLen = 128 / 8
	}

	// Name encryption always uses built-in Go AES through BlockCipher.
	// Content encryption uses BlockCipher only if useOpenssl=false.
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var gcm cipher.AEAD
	if useOpenssl && GCMIV128 {
		// stupidgcm only supports 128-bit IVs
		gcm = stupidgcm.New(key)
	} else {
		gcm, err = goGCMWrapper(blockCipher, IVLen)
		if err != nil {
			panic(err)
		}
	}

	return &CryptoCore{
		BlockCipher: blockCipher,
		Gcm:         gcm,
		GcmIVGen:    &nonceGenerator{nonceLen: IVLen},
		IVLen:       IVLen,
	}
}
