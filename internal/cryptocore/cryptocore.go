// Package cryptocore wraps OpenSSL and Go GCM crypto and provides
// a nonce generator.
package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"fmt"

	"github.com/rfjakob/gocryptfs/internal/siv_aead"
	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
)

type BackendTypeEnum int

const (
	KeyLen     = 32 // AES-256
	AuthTagLen = 16

	_                              = iota // Skip zero
	BackendOpenSSL BackendTypeEnum = iota
	BackendGoGCM   BackendTypeEnum = iota
	BackendAESSIV  BackendTypeEnum = iota
)

type CryptoCore struct {
	// AES-256 block cipher. This is used for EME filename encryption.
	BlockCipher cipher.Block
	// GCM or AES-SIV. This is used for content encryption.
	AEADCipher cipher.AEAD
	// Which backend is behind AEADCipher?
	AEADBackend BackendTypeEnum
	// GCM needs unique IVs (nonces)
	IVGenerator *nonceGenerator
	IVLen       int
}

// "New" returns a new CryptoCore object or panics.
//
// Even though the "GCMIV128" feature flag is now mandatory, we must still
// support 96-bit IVs here because they are used for encrypting the master
// key in gocryptfs.conf.
func New(key []byte, backend BackendTypeEnum, IVBitLen int) *CryptoCore {
	if len(key) != KeyLen {
		panic(fmt.Sprintf("Unsupported key length %d", len(key)))
	}
	// We want the IV size in bytes
	IVLen := IVBitLen / 8

	// Name encryption always uses built-in Go AES through BlockCipher.
	// Content encryption uses BlockCipher only if useOpenssl=false.
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var aeadCipher cipher.AEAD
	switch backend {
	case BackendOpenSSL:
		if IVLen != 16 {
			panic("stupidgcm only supports 128-bit IVs")
		}
		aeadCipher = stupidgcm.New(key)
	case BackendGoGCM:
		aeadCipher, err = goGCMWrapper(blockCipher, IVLen)
	case BackendAESSIV:
		// AES-SIV uses 1/2 of the key for authentication, 1/2 for
		// encryption, so we need a 64-bytes key for AES-256. Derive it from
		// the master key by hashing it with SHA-512.
		key64 := sha512.Sum512(key)
		aeadCipher = siv_aead.New(key64[:])
	default:
		panic("unknown backend cipher")
	}
	if err != nil {
		panic(err)
	}

	return &CryptoCore{
		BlockCipher: blockCipher,
		AEADCipher:  aeadCipher,
		AEADBackend: backend,
		IVGenerator: &nonceGenerator{nonceLen: IVLen},
		IVLen:       IVLen,
	}
}
