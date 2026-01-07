package cryptocore

import (
	"crypto/hkdf"
	"crypto/sha256"
	"log"
)

const (
	// "info" data that HKDF mixes into the generated key to make it unique.
	// For convenience, we use a readable string.
	hkdfInfoEMENames               = "EME filename encryption"
	hkdfInfoGCMContent             = "AES-GCM file content encryption"
	hkdfInfoSIVContent             = "AES-SIV file content encryption"
	hkdfInfoXChaChaPoly1305Content = "XChaCha20-Poly1305 file content encryption"
)

// hkdfDerive derives "outLen" bytes from "masterkey" and "info" using
// HKDF-SHA256 (RFC 5869).
// It returns the derived bytes or panics.
func hkdfDerive(masterkey []byte, info string, outLen int) []byte {
	key, err := hkdf.Key(sha256.New, masterkey, nil, info, outLen)
	if err != nil {
		log.Panicf("hkdfDerive: hkdf failed with error: %v", err)
	}
	return key
}
