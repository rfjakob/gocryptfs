// Package cryptocore wraps OpenSSL and Go GCM crypto and provides
// a nonce generator.
package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"fmt"
	"log"
	"runtime"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/internal/siv_aead"
	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// KeyLen is the cipher key length in bytes.  32 for AES-256.
	KeyLen = 32
	// AuthTagLen is the length of a GCM auth tag in bytes.
	AuthTagLen = 16
)

// AEADTypeEnum indicates the type of AEAD backend in use.
type AEADTypeEnum int

const (
	// BackendOpenSSL specifies the OpenSSL backend.
	BackendOpenSSL AEADTypeEnum = 3
	// BackendGoGCM specifies the Go based GCM backend.
	BackendGoGCM AEADTypeEnum = 4
	// BackendAESSIV specifies an AESSIV backend.
	BackendAESSIV AEADTypeEnum = 5
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
//
// Note: "key" is either the scrypt hash of the password (when decrypting
// a config file) or the masterkey (when finally mounting the filesystem).
func New(key []byte, aeadType AEADTypeEnum, IVBitLen int, useHKDF bool, forceDecode bool) *CryptoCore {
	if len(key) != KeyLen {
		log.Panic(fmt.Sprintf("Unsupported key length %d", len(key)))
	}
	// We want the IV size in bytes
	IVLen := IVBitLen / 8

	// Initialize EME for filename encryption.
	var emeCipher *eme.EMECipher
	var err error
	{
		var emeBlockCipher cipher.Block
		if useHKDF {
			emeKey := hkdfDerive(key, hkdfInfoEMENames, KeyLen)
			emeBlockCipher, err = aes.NewCipher(emeKey)
			for i := range emeKey {
				emeKey[i] = 0
			}
		} else {
			emeBlockCipher, err = aes.NewCipher(key)
		}
		if err != nil {
			log.Panic(err)
		}
		emeCipher = eme.New(emeBlockCipher)
	}

	// Initialize an AEAD cipher for file content encryption.
	var aeadCipher cipher.AEAD
	if aeadType == BackendOpenSSL || aeadType == BackendGoGCM {
		var gcmKey []byte
		if useHKDF {
			gcmKey = hkdfDerive(key, hkdfInfoGCMContent, KeyLen)
		} else {
			gcmKey = append([]byte{}, key...)
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
		for i := range gcmKey {
			gcmKey[i] = 0
		}
	} else if aeadType == BackendAESSIV {
		if IVLen != 16 {
			// SIV supports any nonce size, but we only use 16.
			log.Panic("AES-SIV must use 16-byte nonces")
		}
		// AES-SIV uses 1/2 of the key for authentication, 1/2 for
		// encryption, so we need a 64-bytes key for AES-256. Derive it from
		// the 32-byte master key using HKDF, or, for older filesystems, with
		// SHA256.
		var key64 []byte
		if useHKDF {
			key64 = hkdfDerive(key, hkdfInfoSIVContent, siv_aead.KeyLen)
		} else {
			s := sha512.Sum512(key)
			key64 = s[:]
		}
		aeadCipher = siv_aead.New(key64)
		for i := range key64 {
			key64[i] = 0
		}
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

type wiper interface {
	Wipe()
}

// Wipe tries to wipe secret keys from memory by overwriting them with zeros
// and/or setting references to nil.
//
// This is not bulletproof due to possible GC copies, but
// still raises to bar for extracting the key.
func (c *CryptoCore) Wipe() {
	be := c.AEADBackend
	if be == BackendOpenSSL || be == BackendAESSIV {
		tlog.Debug.Printf("CryptoCore.Wipe: Wiping AEADBackend %d key", be)
		// We don't use "x, ok :=" because we *want* to crash loudly if the
		// type assertion fails.
		w := c.AEADCipher.(wiper)
		w.Wipe()
	} else {
		tlog.Debug.Printf("CryptoCore.Wipe: Only nil'ing stdlib refs")
	}
	// We have no access to the keys (or key-equivalents) stored inside the
	// Go stdlib. Best we can is to nil the references and force a GC.
	c.AEADCipher = nil
	c.EMECipher = nil
	runtime.GC()
}
