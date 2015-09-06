package cryptfs

// CryptFS is the crypto backend of GoCryptFS

import (
	"crypto/cipher"
	"crypto/aes"
)

const (
	NONCE_LEN = 12
	AUTH_TAG_LEN = 16
	DEFAULT_PLAINBS = 4096
)

type CryptFS struct {
	blockCipher cipher.Block
	gcm cipher.AEAD
	plainBS	uint64
	cipherBS uint64
}

func NewCryptFS(key [16]byte, useOpenssl bool) *CryptFS {

	b, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}

	var gcm cipher.AEAD
	if useOpenssl {
		gcm = opensslGCM{key}
	} else {
		gcm, err = cipher.NewGCM(b)
		if err != nil {
			panic(err)
		}
	}

	return &CryptFS{
		blockCipher: b,
		gcm: gcm,
		plainBS: DEFAULT_PLAINBS,
		cipherBS: DEFAULT_PLAINBS + NONCE_LEN + AUTH_TAG_LEN,
	}
}

func (be *CryptFS) PlainBS() uint64 {
	return be.plainBS
}
