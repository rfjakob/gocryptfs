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
	AUTH_TAG_LEN    = 16
	DIRIV_LEN       = 16 // identical to AES block size
	DIRIV_FILENAME  = "gocryptfs.diriv"
)

type CryptFS struct {
	blockCipher cipher.Block
	gcm         cipher.AEAD
	gcmIVLen    int
	gcmIVGen    nonceGenerator
	plainBS     uint64
	cipherBS    uint64
	// Stores an all-zero block of size cipherBS
	allZeroBlock []byte
	// DirIV cache for filename encryption
	DirIVCacheEnc DirIVCache
}

func NewCryptFS(key []byte, useOpenssl bool, plaintextNames bool, GCMIV128 bool) *CryptFS {

	if len(key) != KEY_LEN {
		panic(fmt.Sprintf("Unsupported key length %d", len(key)))
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// We want the IV size in bytes
	gcmIV := 96 / 8
	if GCMIV128 {
		gcmIV = 128 / 8
	}

	var gcm cipher.AEAD
	if useOpenssl {
		gcm = opensslGCM{key}
	} else {
		gcm, err = goGCMWrapper(b, gcmIV)
		if err != nil {
			panic(err)
		}
	}

	plainBS := DEFAULT_PLAINBS
	cipherBS := plainBS + gcmIV + AUTH_TAG_LEN

	return &CryptFS{
		blockCipher:  b,
		gcm:          gcm,
		gcmIVLen:     gcmIV,
		gcmIVGen:     nonceGenerator{nonceLen: gcmIV},
		plainBS:      uint64(plainBS),
		cipherBS:     uint64(cipherBS),
		allZeroBlock: make([]byte, cipherBS),
	}
}

// Get plaintext block size
func (be *CryptFS) PlainBS() uint64 {
	return be.plainBS
}

// Per-block storage overhead
func (be *CryptFS) BlockOverhead() uint64 {
	return be.cipherBS - be.plainBS
}
