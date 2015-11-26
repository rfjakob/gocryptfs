package cryptfs

// Filename encryption / decryption function

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	OpEncrypt = iota
	OpDecrypt
)

// DecryptName - decrypt base64-encoded encrypted filename "cipherName"
func (be *CryptFS) decryptName(cipherName string, iv []byte) (string, error) {

	// Make sure relative symlinks still work after encryption
	// by passing these through unchanged
	if cipherName == "." || cipherName == ".." {
		return cipherName, nil
	}

	bin, err := base64.URLEncoding.DecodeString(cipherName)
	if err != nil {
		return "", err
	}

	if len(bin)%aes.BlockSize != 0 {
		return "", fmt.Errorf("Decoded length %d is not a multiple of the AES block size", len(bin))
	}

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
func (be *CryptFS) encryptName(plainName string, iv []byte) string {

	// Make sure relative symlinks still work after encryption
	// by passing these trough unchanged
	if plainName == "." || plainName == ".." {
		return plainName
	}

	bin := []byte(plainName)
	bin = be.pad16(bin)

	cbc := cipher.NewCBCEncrypter(be.blockCipher, iv)
	cbc.CryptBlocks(bin, bin)

	cipherName64 := base64.URLEncoding.EncodeToString(bin)
	return cipherName64
}


// TranslatePathZeroIV - encrypt or decrypt path using CBC with a constant all-zero IV.
// Just splits the string on "/" and hands the parts to encryptName() / decryptName()
func (be *CryptFS) TranslatePathZeroIV(path string, op int) (string, error) {
	var err error

	// Empty string means root directory
	if path == "" {
		return path, err
	}

	zeroIV := make([]byte, DIRIV_LEN)

	// Run operation on each path component
	var translatedParts []string
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" {
			// This happens on "/foo/bar/" on the front and on the end.
			// Don't panic.
			translatedParts = append(translatedParts, "")
			continue
		}
		var newPart string
		if op == OpEncrypt {
			newPart = be.encryptName(part, zeroIV)
		} else {
			newPart, err = be.decryptName(part, zeroIV)
			if err != nil {
				return "", err
			}
		}
		translatedParts = append(translatedParts, newPart)
	}

	return strings.Join(translatedParts, "/"), err
}

// pad16 - pad filename to 16 byte blocks using standard PKCS#7 padding
// https://tools.ietf.org/html/rfc5652#section-6.3
func (be *CryptFS) pad16(orig []byte) (padded []byte) {
	oldLen := len(orig)
	if oldLen == 0 {
		panic("Padding zero-length string makes no sense")
	}
	padLen := aes.BlockSize - oldLen%aes.BlockSize
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
	if oldLen%aes.BlockSize != 0 {
		return nil, errors.New("Unaligned size")
	}
	// The last byte is always a padding byte
	padByte := orig[oldLen-1]
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


