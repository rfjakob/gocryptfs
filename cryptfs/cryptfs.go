package cryptfs

// CryptFS is the crypto backend of GoCryptFS

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const (
	DEFAULT_PLAINBS = 4096
	KEY_LEN         = 32 // AES-256
	NONCE_LEN       = 12
	AUTH_TAG_LEN    = 16
	BLOCK_OVERHEAD  = NONCE_LEN + AUTH_TAG_LEN
	DIRIV_LEN       = 16 // identical to AES block size
	DIRIV_FILENAME  = "gocryptfs.diriv"
)

type CryptFS struct {
	blockCipher cipher.Block
	gcm         cipher.AEAD
	plainBS     uint64
	cipherBS    uint64
	// Stores an all-zero block of size cipherBS
	allZeroBlock   []byte
	plaintextNames bool
	// DirIV cache for filename encryption
	DirIVCacheEnc DirIVCache
}

func NewCryptFS(key []byte, useOpenssl bool, plaintextNames bool) *CryptFS {

	if len(key) != KEY_LEN {
		panic(fmt.Sprintf("Unsupported key length %d", len(key)))
	}

	b, err := aes.NewCipher(key)
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

	cipherBS := DEFAULT_PLAINBS + NONCE_LEN + AUTH_TAG_LEN

	return &CryptFS{
		blockCipher:    b,
		gcm:            gcm,
		plainBS:        DEFAULT_PLAINBS,
		cipherBS:       uint64(cipherBS),
		allZeroBlock:   make([]byte, cipherBS),
		plaintextNames: plaintextNames,
	}
}

// Get plaintext block size
func (be *CryptFS) PlainBS() uint64 {
	return be.plainBS
}
