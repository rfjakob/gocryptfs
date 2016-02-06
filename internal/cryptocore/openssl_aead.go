package cryptocore

// Implements cipher.AEAD with OpenSSL backend

import (
	"bytes"
	"github.com/spacemonkeygo/openssl"
)

// Supports all nonce sizes
type opensslGCM struct {
	key []byte
}

func (be opensslGCM) Overhead() int {
	return AuthTagLen
}

func (be opensslGCM) NonceSize() int {
	// We support any nonce size
	return -1
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. opensslGCM supports any nonce size.
func (be opensslGCM) Seal(dst, nonce, plaintext, data []byte) []byte {

	// Preallocate output buffer
	var cipherBuf bytes.Buffer
	cipherBuf.Grow(len(dst) + len(plaintext) + AuthTagLen)
	// Output will be appended to dst
	cipherBuf.Write(dst)

	ectx, err := openssl.NewGCMEncryptionCipherCtx(KeyLen*8, nil, be.key, nonce)
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

	l := len(ciphertext)
	tag := ciphertext[l-AuthTagLen : l]
	ciphertext = ciphertext[0 : l-AuthTagLen]
	plainBuf := bytes.NewBuffer(dst)

	dctx, err := openssl.NewGCMDecryptionCipherCtx(KeyLen*8, nil, be.key, nonce)
	if err != nil {
		return nil, err
	}
	err = dctx.ExtraData(data)
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

	return plainBuf.Bytes(), nil
}
