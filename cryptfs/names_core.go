package cryptfs

// Filename encryption / decryption functions

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/rfjakob/eme"
)

// DecryptName - decrypt base64-encoded encrypted filename "cipherName"
// The used encryption is either CBC or EME, depending on the "EMENames" argument.
//
// This function is exported because it allows for a very efficient readdir
// implementation (read IV once, decrypt all names using this function).
func (be *CryptFS) DecryptName(cipherName string, iv []byte, EMENames bool) (string, error) {
	return be.decryptName(cipherName, iv, EMENames)
}

// decryptName - decrypt base64-encoded encrypted filename "cipherName".
// The used encryption is either CBC or EME, depending on the "EMENames" argument.
func (be *CryptFS) decryptName(cipherName string, iv []byte, EMENames bool) (string, error) {

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

	if EMENames {
		bin = eme.Transform(be.blockCipher, iv, bin, eme.DirectionDecrypt)
	} else {
		cbc := cipher.NewCBCDecrypter(be.blockCipher, iv)
		cbc.CryptBlocks(bin, bin)
	}

	bin, err = be.unPad16(bin)
	if err != nil {
		return "", err
	}

	plain := string(bin)
	return plain, err
}

// encryptName - encrypt "plainName", return base64-encoded "cipherName64"
// The used encryption is either CBC or EME, depending on the "EMENames" argument.
func (be *CryptFS) encryptName(plainName string, iv []byte, EMENames bool) (cipherName64 string) {

	// Make sure relative symlinks still work after encryption
	// by passing these trough unchanged
	if plainName == "." || plainName == ".." {
		return plainName
	}

	bin := []byte(plainName)
	bin = be.pad16(bin)

	if EMENames {
		bin = eme.Transform(be.blockCipher, iv, bin, eme.DirectionEncrypt)
	} else {
		cbc := cipher.NewCBCEncrypter(be.blockCipher, iv)
		cbc.CryptBlocks(bin, bin)
	}

	cipherName64 = base64.URLEncoding.EncodeToString(bin)
	return cipherName64
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
