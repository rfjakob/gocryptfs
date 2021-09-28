// Package cryptocore wraps OpenSSL and Go GCM crypto and provides
// a nonce generator.
package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"log"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/siv_aead"
	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// KeyLen is the cipher key length in bytes. All backends use 32 bytes.
	KeyLen = 32
	// AuthTagLen is the length of a authentication tag in bytes.
	// All backends use 16 bytes.
	AuthTagLen = 16
)

// AEADTypeEnum indicates the type of AEAD backend in use.
type AEADTypeEnum struct {
	// Algo is the encryption algorithm. Example: "AES-GCM-256"
	Algo string
	// Lib is the library where Algo is implemented. Either "Go" or "OpenSSL".
	Lib       string
	NonceSize int
}

// String returns something like "AES-GCM-256-OpenSSL"
func (a AEADTypeEnum) String() string {
	return a.Algo + "-" + a.Lib
}

// BackendOpenSSL specifies the OpenSSL AES-256-GCM backend.
// "AES-GCM-256-OpenSSL" in gocryptfs -speed.
var BackendOpenSSL = AEADTypeEnum{"AES-GCM-256", "OpenSSL", 16}

// BackendGoGCM specifies the Go based AES-256-GCM backend.
// "AES-GCM-256-Go" in gocryptfs -speed.
var BackendGoGCM = AEADTypeEnum{"AES-GCM-256", "Go", 16}

// BackendAESSIV specifies an AESSIV backend.
// "AES-SIV-512-Go" in gocryptfs -speed.
var BackendAESSIV = AEADTypeEnum{"AES-SIV-512", "Go", siv_aead.NonceSize}

// BackendXChaCha20Poly1305 specifies XChaCha20-Poly1305-Go.
// "XChaCha20-Poly1305-Go" in gocryptfs -speed.
var BackendXChaCha20Poly1305 = AEADTypeEnum{"XChaCha20-Poly1305", "Go", chacha20poly1305.NonceSizeX}

// BackendXChaCha20Poly1305OpenSSL specifies XChaCha20-Poly1305-OpenSSL.
var BackendXChaCha20Poly1305OpenSSL = AEADTypeEnum{"XChaCha20-Poly1305", "OpenSSL", chacha20poly1305.NonceSizeX}

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
	// IVLen in bytes
	IVLen int
}

// New returns a new CryptoCore object or panics.
//
// Even though the "GCMIV128" feature flag is now mandatory, we must still
// support 96-bit IVs here because they were used for encrypting the master
// key in gocryptfs.conf up to gocryptfs v1.2. v1.3 switched to 128 bits.
//
// Note: "key" is either the scrypt hash of the password (when decrypting
// a config file) or the masterkey (when finally mounting the filesystem).
func New(key []byte, aeadType AEADTypeEnum, IVBitLen int, useHKDF bool) *CryptoCore {
	tlog.Debug.Printf("cryptocore.New: key=%d bytes, aeadType=%v, IVBitLen=%d, useHKDF=%v",
		len(key), aeadType, IVBitLen, useHKDF)

	if len(key) != KeyLen {
		log.Panicf("Unsupported key length of %d bytes", len(key))
	}
	if IVBitLen != 96 && IVBitLen != 128 && IVBitLen != chacha20poly1305.NonceSizeX*8 {
		log.Panicf("Unsupported IV length of %d bits", IVBitLen)
	}

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
			// Filesystems created by gocryptfs v0.7 through v1.2 don't use HKDF.
			// Example: tests/example_filesystems/v0.9
			gcmKey = append([]byte{}, key...)
		}
		switch aeadType {
		case BackendOpenSSL:
			if IVBitLen != 128 {
				log.Panicf("stupidgcm only supports 128-bit IVs, you wanted %d", IVBitLen)
			}
			aeadCipher = stupidgcm.NewAES256GCM(gcmKey)
		case BackendGoGCM:
			goGcmBlockCipher, err := aes.NewCipher(gcmKey)
			if err != nil {
				log.Panic(err)
			}
			aeadCipher, err = cipher.NewGCMWithNonceSize(goGcmBlockCipher, IVBitLen/8)
			if err != nil {
				log.Panic(err)
			}
		default:
			log.Panicf("BUG: unhandled case: %v", aeadType)
		}
		for i := range gcmKey {
			gcmKey[i] = 0
		}
	} else if aeadType == BackendAESSIV {
		if IVBitLen != 128 {
			// SIV supports any nonce size, but we only use 128.
			log.Panicf("AES-SIV must use 128-bit IVs, you wanted %d", IVBitLen)
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
	} else if aeadType == BackendXChaCha20Poly1305 || aeadType == BackendXChaCha20Poly1305OpenSSL {
		// We don't support legacy modes with XChaCha20-Poly1305
		if IVBitLen != chacha20poly1305.NonceSizeX*8 {
			log.Panicf("XChaCha20-Poly1305 must use 192-bit IVs, you wanted %d", IVBitLen)
		}
		if !useHKDF {
			log.Panic("XChaCha20-Poly1305 must use HKDF, but it is disabled")
		}
		derivedKey := hkdfDerive(key, hkdfInfoXChaChaPoly1305Content, chacha20poly1305.KeySize)
		if aeadType == BackendXChaCha20Poly1305 {
			aeadCipher, err = chacha20poly1305.NewX(derivedKey)
		} else if aeadType == BackendXChaCha20Poly1305OpenSSL {
			aeadCipher = stupidgcm.NewXchacha20poly1305(derivedKey)
		} else {
			log.Panicf("BUG: unhandled case: %v", aeadType)
		}
		if err != nil {
			log.Panic(err)
		}
	} else {
		log.Panicf("unknown cipher backend %q", aeadType)
	}

	if aeadCipher.NonceSize()*8 != IVBitLen {
		log.Panicf("Mismatched aeadCipher.NonceSize*8=%d and IVBitLen=%d bits",
			aeadCipher.NonceSize()*8, IVBitLen)
	}

	return &CryptoCore{
		EMECipher:   emeCipher,
		AEADCipher:  aeadCipher,
		AEADBackend: aeadType,
		IVGenerator: &nonceGenerator{nonceLen: IVBitLen / 8},
		IVLen:       IVBitLen / 8,
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
		tlog.Debug.Printf("CryptoCore.Wipe: Wiping AEADBackend %q key", be)
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
