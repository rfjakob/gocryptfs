// Package cryptocore wraps OpenSSL and Go GCM crypto and provides
// a nonce generator.
package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"fmt"
	"log"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/internal/siv_aead"
	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
)

// AEADTypeEnum indicates the type of AEAD backend in use.
type AEADTypeEnum int

const (
	// KeyLen is the cipher key length in bytes.  32 for AES-256.
	KeyLen = 32
	// AuthTagLen is the length of a GCM auth tag in bytes.
	AuthTagLen = 16

	_ = iota // Skip zero
	// BackendOpenSSL specifies the OpenSSL backend.
	BackendOpenSSL AEADTypeEnum = iota
	// BackendGoGCM specifies the Go based GCM backend.
	BackendGoGCM AEADTypeEnum = iota
	// BackendAESSIV specifies an AESSIV backend.
	BackendAESSIV AEADTypeEnum = iota
)

// CryptoCore is the low level crypto implementation.
type CryptoCore struct {
	// EME is used for filename encryption.
	EMECipher *eme.EMECipher
	// GCM or AES-SIV. This is used for content encryption.
	AEADCipher cipher.AEAD
	// Which backend is behind AEADCipher?
	AEADBackend AEADTypeEnum
	// GCM needs unique IVs (nonces)
	IVGenerator *nonceGenerator
	IVLen       int
}

// New returns a new CryptoCore object or panics.
//
// Even though the "GCMIV128" feature flag is now mandatory, we must still
// support 96-bit IVs here because they were used for encrypting the master
// key in gocryptfs.conf up to gocryptfs v1.2. v1.3 switched to 128 bits.
func New(key []byte, aeadType AEADTypeEnum, IVBitLen int, useHKDF bool, forceDecode bool) *CryptoCore {
	if len(key) != KeyLen {
		log.Panic(fmt.Sprintf("Unsupported key length %d", len(key)))
	}
	// We want the IV size in bytes
	IVLen := IVBitLen / 8

	// Initialize EME for filename encryption.
	var emeCipher *eme.EMECipher
	{
		emeKey := key
		if useHKDF {
			info := "EME filename encryption"
			emeKey = hkdfDerive(key, info, KeyLen)
		}
		emeBlockCipher, err := aes.NewCipher(emeKey)
		if err != nil {
			log.Panic(err)
		}
		emeCipher = eme.New(emeBlockCipher)
	}

	// Initilize an AEAD cipher for file content encryption.
	var aeadCipher cipher.AEAD
	if aeadType == BackendOpenSSL || aeadType == BackendGoGCM {
		gcmKey := key
		if useHKDF {
			info := "AES-GCM file content encryption"
			gcmKey = hkdfDerive(key, info, KeyLen)
		}
		switch aeadType {
		case BackendOpenSSL:
			if IVLen != 16 {
				log.Panic("stupidgcm only supports 128-bit IVs")
			}
			aeadCipher = stupidgcm.New(gcmKey, forceDecode)
		case BackendGoGCM:
			goGcmBlockCipher, err := aes.NewCipher(gcmKey)
			if err != nil {
				log.Panic(err)
			}
			aeadCipher, err = cipher.NewGCMWithNonceSize(goGcmBlockCipher, IVLen)
			if err != nil {
				log.Panic(err)
			}
		}
	} else if aeadType == BackendAESSIV {
		if IVLen != 16 {
			// SIV supports any nonce size, but we only use 16.
			log.Panic("AES-SIV must use 16-byte nonces")
		}
		var key64 []byte
		if useHKDF {
			info := "AES-SIV file content encryption"
			key64 = hkdfDerive(key, info, siv_aead.KeyLen)
		} else {
			// AES-SIV uses 1/2 of the key for authentication, 1/2 for
			// encryption, so we need a 64-bytes key for AES-256. Derive it from
			// the master key by hashing it with SHA-512.
			s := sha512.Sum512(key)
			key64 = s[:]
		}
		aeadCipher = siv_aead.New(key64)
	} else {
		log.Panic("unknown backend cipher")
	}

	return &CryptoCore{
		EMECipher:   emeCipher,
		AEADCipher:  aeadCipher,
		AEADBackend: aeadType,
		IVGenerator: &nonceGenerator{nonceLen: IVLen},
		IVLen:       IVLen,
	}
}
