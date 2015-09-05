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

func NewCryptFS(key [16]byte) *CryptFS {

	b, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}

	g, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}

	return &CryptFS{
		blockCipher: b,
		gcm: g,
		plainBS: DEFAULT_PLAINBS,
		cipherBS: DEFAULT_PLAINBS + NONCE_LEN + AUTH_TAG_LEN,
	}
}

func (be *CryptFS) PlainBS() uint64 {
	return be.plainBS
}
