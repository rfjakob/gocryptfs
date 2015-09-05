package cryptfs

import (
	"crypto/cipher"
	"crypto/aes"
	"fmt"
	"strings"
	"encoding/base64"
	"errors"
)

const (
	NONCE_LEN = 12
	AUTH_TAG_LEN = 16
	DEFAULT_PLAINBS = 4096

	ENCRYPT = true
	DECRYPT = false
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

/*
func (fs *CryptFS) NewFile(f *os.File) *CryptFile {
	return &CryptFile {
		file: f,
		gcm: fs.gcm,
		plainBS: fs.plainBS,
		cipherBS: fs.cipherBS,
	}
}
*/

func (be *CryptFS) PlainBS() uint64 {
	return be.plainBS
}

// DecryptName - decrypt filename
func (be *CryptFS) decryptName(cipherName string) (string, error) {

	bin, err := base64.URLEncoding.DecodeString(cipherName)
	if err != nil {
		return "", err
	}

	if len(bin) % aes.BlockSize != 0 {
		return "", errors.New(fmt.Sprintf("Name len=%d is not a multiple of 16", len(bin)))
	}

	iv := make([]byte, aes.BlockSize) // TODO ?
	cbc := cipher.NewCBCDecrypter(be.blockCipher, iv)
	cbc.CryptBlocks(bin, bin)

	bin, err = be.unPad16(bin)
	if err != nil {
		return "", err
	}

	plain := string(bin)
	return plain, err
}

// EncryptName - encrypt filename
func (be *CryptFS) encryptName(plainName string) string {

	bin := []byte(plainName)
	bin = be.pad16(bin)

	iv := make([]byte, 16) // TODO ?
	cbc := cipher.NewCBCEncrypter(be.blockCipher, iv)
	cbc.CryptBlocks(bin, bin)

	cipherName64 := base64.URLEncoding.EncodeToString(bin)

	return cipherName64
}

// TranslatePath - encrypt or decrypt path. Just splits the string on "/"
// and hands the parts to EncryptName() / DecryptName()
func (be *CryptFS) translatePath(path string, op bool) (string, error) {
	var err error

	// Empty string means root directory
	if path == "" {
		return path, err
	}

	// Run operation on each path component
	var translatedParts []string
	parts := strings.Split(path, "/")
	for _, part := range parts {
		var newPart string
		if op == ENCRYPT {
			newPart = be.encryptName(part)
		} else {
			newPart, err = be.decryptName(part)
			if err != nil {
				return "", err
			}
		}
		translatedParts = append(translatedParts, newPart)
	}

	return strings.Join(translatedParts, "/"), err
}

// EncryptPath - encrypt filename or path. Just hands it to TranslatePath().
func (be *CryptFS) EncryptPath(path string) string {
	newPath, _ := be.translatePath(path, ENCRYPT)
	return newPath
}

// DecryptPath - decrypt filename or path. Just hands it to TranslatePath().
func (be *CryptFS) DecryptPath(path string) (string, error) {
	return be.translatePath(path, DECRYPT)
}

// PlainSize - calculate plaintext size from ciphertext size
func (be *CryptFS) PlainSize(size uint64) uint64 {
	// Zero sized files stay zero-sized
	if size > 0 {
		overhead := be.cipherBS - be.plainBS
		nBlocks := (size + be.cipherBS - 1) / be.cipherBS
		size -= nBlocks * overhead
	}
	return size
}


// plainSizeFromCipherSize - calculate plaintext size from ciphertext size
func (be *CryptFS) plainSizeFromCipherSize(size int64) int64 {
	if size > 0 {

	}
	return size
}
// pad16 - pad filename to 16 byte blocks using standard PKCS#7 padding
// https://tools.ietf.org/html/rfc5652#section-6.3
func (be *CryptFS) pad16(orig []byte) (padded []byte) {
	oldLen := len(orig)
	if oldLen == 0 {
		panic("Padding zero-length string makes no sense")
	}
	padLen := aes.BlockSize - oldLen % aes.BlockSize
	if padLen == 0 {
		padLen = aes.BlockSize
	}
	newLen := oldLen + padLen
	padded = make([]byte, newLen)
	copy(padded, orig)
	padByte := byte(padLen)
	for i := oldLen; i < newLen; i++ {
		padded[i] = padByte
	}
	return padded
}

// unPad16 - remove padding
func (be *CryptFS) unPad16(orig []byte) ([]byte, error) {
	oldLen := len(orig)
	if oldLen % aes.BlockSize != 0 {
		return nil, errors.New("Unaligned size")
	}
	// The last byte is always a padding byte
	padByte := orig[oldLen -1]
	// The padding byte's value is the padding length
	padLen := int(padByte)
	// Padding must be at least 1 byte
	if padLen <= 0 {
		return nil, errors.New("Padding cannot be zero-length")
	}
	// Larger paddings make no sense
	if padLen > aes.BlockSize {
		return nil, errors.New("Padding cannot be larger than 16")
	}
	// All padding bytes must be identical
	for i := oldLen - padLen; i < oldLen; i++ {
		if orig[i] != padByte {
			return nil, errors.New(fmt.Sprintf("Padding byte at i=%d is invalid", i))
		}
	}
	newLen := oldLen - padLen
	// Padding an empty string makes no sense
	if newLen == 0 {
		return nil, errors.New("Unpadded length is zero")
	}
	return orig[0:newLen], nil
}
