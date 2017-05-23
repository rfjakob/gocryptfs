package nametransform

import (
	"crypto/aes"
	"errors"
	"fmt"
	"log"
)

// pad16 - pad data to AES block size (=16 byte) using standard PKCS#7 padding
// https://tools.ietf.org/html/rfc5652#section-6.3
func pad16(orig []byte) (padded []byte) {
	oldLen := len(orig)
	if oldLen == 0 {
		log.Panic("Padding zero-length string makes no sense")
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
func unPad16(padded []byte) ([]byte, error) {
	oldLen := len(padded)
	if oldLen == 0 {
		return nil, errors.New("Empty input")
	}
	if oldLen%aes.BlockSize != 0 {
		return nil, errors.New("Unaligned size")
	}
	// The last byte is always a padding byte
	padByte := padded[oldLen-1]
	// The padding byte's value is the padding length
	padLen := int(padByte)
	// Padding must be at least 1 byte
	if padLen == 0 {
		return nil, errors.New("Padding cannot be zero-length")
	}
	// Padding more than 16 bytes make no sense
	if padLen > aes.BlockSize {
		return nil, fmt.Errorf("Padding too long, padLen=%d > 16", padLen)
	}
	// Padding cannot be as long as (or longer than) the whole string,
	if padLen >= oldLen {
		return nil, fmt.Errorf("Padding too long, oldLen=%d >= padLen=%d", oldLen, padLen)
	}
	// All padding bytes must be identical
	for i := oldLen - padLen; i < oldLen; i++ {
		if padded[i] != padByte {
			return nil, fmt.Errorf("Padding byte at i=%d is invalid", i)
		}
	}
	newLen := oldLen - padLen
	return padded[0:newLen], nil
}
