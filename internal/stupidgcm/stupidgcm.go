// Package stupidgcm is a thin wrapper for OpenSSL's GCM encryption and
// decryption functions. It only support 32-byte keys and 16-bit IVs.
package stupidgcm

// #include <openssl/evp.h>
// #cgo pkg-config: libcrypto
import "C"

import (
	"fmt"
	"log"
	"unsafe"
)

const (
	keyLen = 32
	ivLen  = 16
	tagLen = 16
)

// stupidGCM implements the cipher.AEAD interface
type stupidGCM struct {
	key []byte
}

func New(key []byte) stupidGCM {
	if len(key) != keyLen {
		log.Panicf("Only %d-byte keys are supported", keyLen)
	}
	return stupidGCM{key: key}
}

func (g stupidGCM) NonceSize() int {
	return ivLen
}

func (g stupidGCM) Overhead() int {
	return tagLen
}

// Seal - encrypt "in" using "iv" and "authData" and append the result to "dst"
func (g stupidGCM) Seal(dst, iv, in, authData []byte) []byte {
	if len(iv) != ivLen {
		log.Panicf("Only %d-byte IVs are supported", ivLen)
	}
	if len(in) == 0 {
		log.Panic("Zero-length input data is not supported")
	}
	buf := make([]byte, len(in)+tagLen)

	// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode

	// Create scratch space "context"
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		panic("EVP_CIPHER_CTX_new failed")
	}

	// Set cipher to AES-256
	if C.EVP_EncryptInit_ex(ctx, C.EVP_aes_256_gcm(), nil, nil, nil) != 1 {
		panic("EVP_EncryptInit_ex I failed")
	}

	// Use 16-byte IV
	if C.EVP_CIPHER_CTX_ctrl(ctx, C.EVP_CTRL_GCM_SET_IVLEN, ivLen, nil) != 1 {
		panic("EVP_CIPHER_CTX_ctrl EVP_CTRL_GCM_SET_IVLEN failed")
	}

	// Set key and IV
	if C.EVP_EncryptInit_ex(ctx, nil, nil, (*C.uchar)(&g.key[0]), (*C.uchar)(&iv[0])) != 1 {
		panic("EVP_EncryptInit_ex II failed")
	}

	// Provide authentication data
	var resultLen C.int
	if C.EVP_EncryptUpdate(ctx, nil, &resultLen, (*C.uchar)(&authData[0]), C.int(len(authData))) != 1 {
		panic("EVP_EncryptUpdate authData failed")
	}
	if int(resultLen) != len(authData) {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Encrypt "in" into "buf"
	if C.EVP_EncryptUpdate(ctx, (*C.uchar)(&buf[0]), &resultLen, (*C.uchar)(&in[0]), C.int(len(in))) != 1 {
		panic("EVP_EncryptUpdate failed")
	}
	if int(resultLen) != len(in) {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Finalise encryption
	// Because GCM is a stream encryption, this will not write out any data.
	dummy := make([]byte, 16)
	if C.EVP_EncryptFinal_ex(ctx, (*C.uchar)(&dummy[0]), &resultLen) != 1 {
		panic("EVP_EncryptFinal_ex failed")
	}
	if resultLen != 0 {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Get GMAC tag and append it to the ciphertext in "buf"
	if C.EVP_CIPHER_CTX_ctrl(ctx, C.EVP_CTRL_GCM_GET_TAG, tagLen, (unsafe.Pointer)(&buf[len(in)])) != 1 {
		panic("EVP_CIPHER_CTX_ctrl EVP_CTRL_GCM_GET_TAG failed")
	}

	// Free scratch space
	C.EVP_CIPHER_CTX_free(ctx)

	return append(dst, buf...)
}

// Open - decrypt "in" using "iv" and "authData" and append the result to "dst"
func (g stupidGCM) Open(dst, iv, in, authData []byte) ([]byte, error) {
	if len(iv) != ivLen {
		log.Panicf("Only %d-byte IVs are supported", ivLen)
	}
	if len(in) <= tagLen {
		log.Panic("Input data too short")
	}
	buf := make([]byte, len(in)-tagLen)
	ciphertext := in[:len(in)-tagLen]
	tag := in[len(in)-tagLen:]

	// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode

	// Create scratch space "context"
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		panic("EVP_CIPHER_CTX_new failed")
	}

	// Set cipher to AES-256
	if C.EVP_DecryptInit_ex(ctx, C.EVP_aes_256_gcm(), nil, nil, nil) != 1 {
		panic("EVP_DecryptInit_ex I failed")
	}

	// Use 16-byte IV
	if C.EVP_CIPHER_CTX_ctrl(ctx, C.EVP_CTRL_GCM_SET_IVLEN, ivLen, nil) != 1 {
		panic("EVP_CIPHER_CTX_ctrl EVP_CTRL_GCM_SET_IVLEN failed")
	}

	// Set key and IV
	if C.EVP_DecryptInit_ex(ctx, nil, nil, (*C.uchar)(&g.key[0]), (*C.uchar)(&iv[0])) != 1 {
		panic("EVP_DecryptInit_ex II failed")
	}

	// Set expected GMAC tag
	if C.EVP_CIPHER_CTX_ctrl(ctx, C.EVP_CTRL_GCM_SET_TAG, tagLen, (unsafe.Pointer)(&tag[0])) != 1 {
		panic("EVP_CIPHER_CTX_ctrl failed")
	}

	// Provide authentication data
	var resultLen C.int
	if C.EVP_DecryptUpdate(ctx, nil, &resultLen, (*C.uchar)(&authData[0]), C.int(len(authData))) != 1 {
		panic("EVP_DecryptUpdate authData failed")
	}
	if int(resultLen) != len(authData) {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Decrypt "ciphertext" into "buf"
	if C.EVP_DecryptUpdate(ctx, (*C.uchar)(&buf[0]), &resultLen, (*C.uchar)(&ciphertext[0]), C.int(len(ciphertext))) != 1 {
		panic("EVP_DecryptUpdate failed")
	}
	if int(resultLen) != len(ciphertext) {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Check GMAC
	dummy := make([]byte, 16)
	res := C.EVP_DecryptFinal_ex(ctx, (*C.uchar)(&dummy[0]), &resultLen)
	if resultLen != 0 {
		log.Panicf("Unexpected length %d", resultLen)
	}

	// Free scratch space
	C.EVP_CIPHER_CTX_free(ctx)

	if res != 1 {
		return nil, fmt.Errorf("stupidgcm: message authentication failed")
	}

	return append(dst, buf...), nil
}
