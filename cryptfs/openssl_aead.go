package cryptfs

// Implements cipher.AEAD with OpenSSL backend

import (
	"bytes"
	"github.com/spacemonkeygo/openssl"
)

type opensslGCM struct {
	key []byte
}

func (be opensslGCM) Overhead() int {
	return AUTH_TAG_LEN
}

func (be opensslGCM) NonceSize() int {
	return NONCE_LEN
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
func (be opensslGCM) Seal(dst, nonce, plaintext, data []byte) []byte {

	cipherBuf := bytes.NewBuffer(dst)

	ectx, err := openssl.NewGCMEncryptionCipherCtx(KEY_LEN*8, nil, be.key, nonce)
	if err != nil {
		panic(err)
	}
	err = ectx.ExtraData(data)
	if err != nil {
		panic(err)
	}
	part, err := ectx.EncryptUpdate(plaintext)
	if err != nil {
		panic(err)
	}
	cipherBuf.Write(part)
	part, err = ectx.EncryptFinal()
	if err != nil {
		panic(err)
	}
	cipherBuf.Write(part)
	part, err = ectx.GetTag()
	if err != nil {
		panic(err)
	}
	cipherBuf.Write(part)

	return cipherBuf.Bytes()
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// The ciphertext and dst may alias exactly or not at all.
func (be opensslGCM) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {

	if len(data) > 0 {
		panic("Extra data is not supported")
	}

	l := len(ciphertext)
	tag := ciphertext[l-AUTH_TAG_LEN : l]
	ciphertext = ciphertext[0 : l-AUTH_TAG_LEN]
	plainBuf := bytes.NewBuffer(dst)

	dctx, err := openssl.NewGCMDecryptionCipherCtx(KEY_LEN*8, nil, be.key, nonce)
	if err != nil {
		return nil, err
	}
	part, err := dctx.DecryptUpdate(ciphertext)
	if err != nil {
		return nil, err
	}
	plainBuf.Write(part)
	err = dctx.SetTag(tag)
	if err != nil {
		return nil, err
	}
	part, err = dctx.DecryptFinal()
	if err != nil {
		return nil, err
	}
	plainBuf.Write(part)
	err = dctx.ExtraData(data)
	if err != nil {
		return nil, err
	}

	return plainBuf.Bytes(), nil
}
