package gocryptfs

import (
	"crypto/cipher"
	"crypto/aes"
)

const (
	NONCE_LEN = 12
	AUTH_TAG_LEN = 16
	DEFAULT_PLAINBS = 4096

	ENCRYPT = true
	DECRYPT = false
)

type Backend struct {
	blockCipher cipher.Block
	gcm cipher.AEAD
	plainBS	int64
	cipherBS int64
}

func New(key [16]byte) *Backend {

	b, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}

	g, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}

	return &Backend{
		blockCipher: b,
		gcm: g,
		plainBS: DEFAULT_PLAINBS,
		cipherBS: DEFAULT_PLAINBS + NONCE_LEN + AUTH_TAG_LEN,
	}
}
