// +build !without_openssl

package stupidgcm

// #include <openssl/evp.h>
// #cgo pkg-config: libcrypto
import "C"

import (
	"crypto/cipher"
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
)

type stupidChacha20poly1305 struct {
	key   [chacha20poly1305.KeySize]byte
	wiped bool
}

// Verify that we satisfy the cipher.AEAD interface
var _ cipher.AEAD = &stupidChacha20poly1305{}

func newChacha20poly1305(key []byte) cipher.AEAD {
	if len(key) != chacha20poly1305.KeySize {
		log.Panicf("Only %d-byte keys are supported, you passed %d bytes", chacha20poly1305.KeySize, len(key))
	}
	ret := new(stupidChacha20poly1305)
	copy(ret.key[:], key)
	return ret
}

// NonceSize returns the required size of the nonce / IV.
func (g *stupidChacha20poly1305) NonceSize() int {
	return chacha20poly1305.NonceSize
}

// Overhead returns the number of bytes that are added for authentication.
func (g *stupidChacha20poly1305) Overhead() int {
	return tagLen
}

// Seal encrypts "in" using "iv" and "authData" and append the result to "dst"
func (g *stupidChacha20poly1305) Seal(dst, iv, in, authData []byte) []byte {
	if g.wiped {
		panic("BUG: tried to use wiped key")
	}
	if len(iv) != g.NonceSize() {
		log.Panicf("Only %d-byte IVs are supported, you passed %d bytes", g.NonceSize(), len(iv))
	}
	if len(in) == 0 {
		log.Panic("Zero-length input data is not supported")
	}
	if len(g.key) != chacha20poly1305.KeySize {
		log.Panicf("Wrong key length: %d. Key has been wiped?", len(g.key))
	}

	// If the "dst" slice is large enough we can use it as our output buffer
	outLen := len(in) + tagLen
	var buf []byte
	inplace := false
	if cap(dst)-len(dst) >= outLen {
		inplace = true
		buf = dst[len(dst) : len(dst)+outLen]
	} else {
		buf = make([]byte, outLen)
	}

	// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode

	// Create scratch space "context"
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		log.Panic("EVP_CIPHER_CTX_new failed")
	}

	// Set cipher
	if C.EVP_EncryptInit_ex(ctx, C.EVP_chacha20_poly1305(), nil, nil, nil) != 1 {
		log.Panic("EVP_EncryptInit_ex I failed")
	}

	// Set key and IV
	if C.EVP_EncryptInit_ex(ctx, nil, nil, (*C.uchar)(&g.key[0]), (*C.uchar)(&iv[0])) != 1 {
		log.Panic("EVP_EncryptInit_ex II failed")
	}

	// Provide authentication data
	var resultLen C.int
	if C.EVP_EncryptUpdate(ctx, nil, &resultLen, (*C.uchar)(&authData[0]), C.int(len(authData))) != 1 {
		log.Panic("EVP_EncryptUpdate authData failed")
	}
	if int(resultLen) != len(authData) {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Encrypt "in" into "buf"
	if C.EVP_EncryptUpdate(ctx, (*C.uchar)(&buf[0]), &resultLen, (*C.uchar)(&in[0]), C.int(len(in))) != 1 {
		log.Panic("EVP_EncryptUpdate failed")
	}
	if int(resultLen) != len(in) {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Finalise encryption
	// Because GCM is a stream encryption, this will not write out any data.
	dummy := make([]byte, 16)
	if C.EVP_EncryptFinal_ex(ctx, (*C.uchar)(&dummy[0]), &resultLen) != 1 {
		log.Panic("EVP_EncryptFinal_ex failed")
	}
	if resultLen != 0 {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Get MAC tag and append it to the ciphertext in "buf"
	if C.EVP_CIPHER_CTX_ctrl(ctx, C.EVP_CTRL_AEAD_GET_TAG, tagLen, (unsafe.Pointer)(&buf[len(in)])) != 1 {
		log.Panic("EVP_CIPHER_CTX_ctrl EVP_CTRL_AEAD_GET_TAG failed")
	}

	// Free scratch space
	C.EVP_CIPHER_CTX_free(ctx)

	if inplace {
		return dst[:len(dst)+outLen]
	}
	return append(dst, buf...)
}

// Open decrypts "in" using "iv" and "authData" and append the result to "dst"
func (g *stupidChacha20poly1305) Open(dst, iv, in, authData []byte) ([]byte, error) {
	if g.wiped {
		panic("BUG: tried to use wiped key")
	}
	if len(iv) != g.NonceSize() {
		log.Panicf("Only %d-byte IVs are supported", g.NonceSize())
	}
	if len(g.key) != chacha20poly1305.KeySize {
		log.Panicf("Wrong key length: %d. Key has been wiped?", len(g.key))
	}
	if len(in) <= tagLen {
		return nil, fmt.Errorf("stupidChacha20poly1305: input data too short (%d bytes)", len(in))
	}

	// If the "dst" slice is large enough we can use it as our output buffer
	outLen := len(in) - tagLen
	var buf []byte
	inplace := false
	if cap(dst)-len(dst) >= outLen {
		inplace = true
		buf = dst[len(dst) : len(dst)+outLen]
	} else {
		buf = make([]byte, len(in)-tagLen)
	}

	ciphertext := in[:len(in)-tagLen]
	tag := in[len(in)-tagLen:]

	// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode

	// Create scratch space "context"
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		log.Panic("EVP_CIPHER_CTX_new failed")
	}

	// Set cipher to AES-256
	if C.EVP_DecryptInit_ex(ctx, C.EVP_chacha20_poly1305(), nil, nil, nil) != 1 {
		log.Panic("EVP_DecryptInit_ex I failed")
	}

	// Set key and IV
	if C.EVP_DecryptInit_ex(ctx, nil, nil, (*C.uchar)(&g.key[0]), (*C.uchar)(&iv[0])) != 1 {
		log.Panic("EVP_DecryptInit_ex II failed")
	}

	// Set expected MAC tag
	if C.EVP_CIPHER_CTX_ctrl(ctx, C.EVP_CTRL_AEAD_SET_TAG, tagLen, (unsafe.Pointer)(&tag[0])) != 1 {
		log.Panic("EVP_CIPHER_CTX_ctrl EVP_CTRL_AEAD_SET_TAG failed")
	}

	// Provide authentication data
	var resultLen C.int
	if C.EVP_DecryptUpdate(ctx, nil, &resultLen, (*C.uchar)(&authData[0]), C.int(len(authData))) != 1 {
		log.Panic("EVP_DecryptUpdate authData failed")
	}
	if int(resultLen) != len(authData) {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Decrypt "ciphertext" into "buf"
	if C.EVP_DecryptUpdate(ctx, (*C.uchar)(&buf[0]), &resultLen, (*C.uchar)(&ciphertext[0]), C.int(len(ciphertext))) != 1 {
		log.Panic("EVP_DecryptUpdate failed")
	}
	if int(resultLen) != len(ciphertext) {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Check MAC
	dummy := make([]byte, 16)
	res := C.EVP_DecryptFinal_ex(ctx, (*C.uchar)(&dummy[0]), &resultLen)
	if resultLen != 0 {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Free scratch space
	C.EVP_CIPHER_CTX_free(ctx)

	if res != 1 {
		return nil, ErrAuth
	}

	if inplace {
		return dst[:len(dst)+outLen], nil
	}
	return append(dst, buf...), nil
}

// Wipe tries to wipe the key from memory by overwriting it with zeros.
//
// This is not bulletproof due to possible GC copies, but
// still raises the bar for extracting the key.
func (g *stupidChacha20poly1305) Wipe() {
	g.wiped = true
	for i := range g.key {
		g.key[i] = 0
	}
}
