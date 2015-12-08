package benchmark

// Benchmark go built-int GCM against spacemonkey openssl bindings
//
// Note: This is deprecated in favor of the benchmarks integrated in cryptfs.
//
// Run benchmark:
// go test -bench=.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/rfjakob/gocryptfs/cryptfs"
	"github.com/spacemonkeygo/openssl"
	"os"
	"testing"
)

func TestMain(m *testing.M) {

	fmt.Printf("Benchmarking AES-GCM-%d with 4kB block size\n", cryptfs.KEY_LEN*8)

	r := m.Run()
	os.Exit(r)
}

func BenchmarkGoEnc4K(b *testing.B) {
	buf := make([]byte, 1024*4)
	b.SetBytes(int64(len(buf)))

	var key [cryptfs.KEY_LEN]byte
	var nonce [12]byte
	aes, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(aes)
	var out []byte
	// This would be fileID + blockNo
	aData := make([]byte, 24)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aesgcm.Seal(out[:0], nonce[:], buf, aData)
	}
}

func BenchmarkGoDec4K(b *testing.B) {
	buf := make([]byte, 1024*4)
	b.SetBytes(int64(len(buf)))

	var key [cryptfs.KEY_LEN]byte
	var nonce [12]byte
	aes, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(aes)
	var out []byte
	out = aesgcm.Seal(out[:0], nonce[:], buf, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aesgcm.Open(buf[:0], nonce[:], out, nil)
		if err != nil {
			b.Errorf("Open: %v", err)
		}
	}
}

func BenchmarkOpensslEnc4K(b *testing.B) {
	buf := make([]byte, 1024*4)
	b.SetBytes(int64(len(buf)))

	var key [cryptfs.KEY_LEN]byte
	var nonce [12]byte

	// This would be fileID + blockNo
	aData := make([]byte, 24)

	var ciphertext bytes.Buffer
	var part []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext.Reset()
		ectx, err := openssl.NewGCMEncryptionCipherCtx(cryptfs.KEY_LEN*8, nil, key[:], nonce[:])
		if err != nil {
			b.FailNow()
		}
		err = ectx.ExtraData(aData)
		if err != nil {
			b.FailNow()
		}
		part, err = ectx.EncryptUpdate(buf)
		if err != nil {
			b.FailNow()
		}
		ciphertext.Write(part)
		part, err = ectx.EncryptFinal()
		if err != nil {
			b.FailNow()
		}
		ciphertext.Write(part)
		part, err = ectx.GetTag()
		if err != nil {
			b.FailNow()
		}
		ciphertext.Write(part)
	}
}

func BenchmarkOpensslDec4K(b *testing.B) {
	buf := makeOpensslCiphertext()
	b.SetBytes(int64(1024 * 4))

	tag := buf[4096:]
	buf = buf[0:4096]

	var key [cryptfs.KEY_LEN]byte
	var nonce [12]byte

	var plaintext bytes.Buffer
	var part []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plaintext.Reset()
		dctx, err := openssl.NewGCMDecryptionCipherCtx(cryptfs.KEY_LEN*8, nil, key[:], nonce[:])
		if err != nil {
			b.FailNow()
		}
		part, err = dctx.DecryptUpdate(buf)
		if err != nil {
			b.FailNow()
		}
		plaintext.Write(part)
		err = dctx.SetTag(tag)
		if err != nil {
			b.FailNow()
		}
		part, err = dctx.DecryptFinal()
		if err != nil {
			b.FailNow()
		}
		plaintext.Write(part)
	}
}

func makeOpensslCiphertext() []byte {
	buf := make([]byte, 1024*4)
	var key [cryptfs.KEY_LEN]byte
	var nonce [12]byte
	var ciphertext bytes.Buffer
	var part []byte

	ectx, _ := openssl.NewGCMEncryptionCipherCtx(cryptfs.KEY_LEN*8, nil, key[:], nonce[:])
	part, _ = ectx.EncryptUpdate(buf)
	ciphertext.Write(part)
	part, _ = ectx.EncryptFinal()
	ciphertext.Write(part)
	part, _ = ectx.GetTag()
	ciphertext.Write(part)

	return ciphertext.Bytes()
}
