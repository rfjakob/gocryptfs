//go:build !without_aegis && cgo
// +build !without_aegis,cgo

package stupidgcm

import (
	"crypto/cipher"
	"log"

	"github.com/aegis-aead/go-libaegis/aegis128x2"
	"github.com/aegis-aead/go-libaegis/common"
)

const (
	// BuiltWithoutAegis indicates if aegis been disabled at compile-time
	BuiltWithoutAegis = !common.Available

	// Aegis supports 16 and 32 bit tags
	AegisTagLen = 16
)

type stupidAegis struct {
	aead cipher.AEAD
}

// Verify that we satisfy the cipher.AEAD interface
var _ cipher.AEAD = &stupidAegis{}

func (*stupidAegis) NonceSize() int {
	return aegis128x2.NonceSize
}

func (*stupidAegis) Overhead() int {
	return AegisTagLen
}

func NewAegis(key []byte) cipher.AEAD {
	aead, err := aegis128x2.New(key, AegisTagLen)
	if err != nil {
		log.Panic(err)
	}
	return &stupidAegis{
		aead: aead,
	}
}

func (x *stupidAegis) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return x.aead.Seal(dst, nonce, plaintext, additionalData)
}

func (x *stupidAegis) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return x.aead.Open(dst, nonce, ciphertext, additionalData)
}

func (x *stupidAegis) Wipe() {
	x.aead.(*aegis128x2.Aegis128X2).Wipe()
}
