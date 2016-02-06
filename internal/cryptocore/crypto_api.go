package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
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

func New(key []byte, useOpenssl bool, GCMIV128 bool) *CryptoCore {

	if len(key) != KeyLen {
		panic(fmt.Sprintf("Unsupported key length %d", len(key)))
	}

	// We want the IV size in bytes
	IVLen := 96 / 8
	if GCMIV128 {
		IVLen = 128 / 8
	}

	// We always use built-in Go crypto for blockCipher because it is not
	// performance-critical.
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var gcm cipher.AEAD
	if useOpenssl {
		gcm = opensslGCM{key}
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
