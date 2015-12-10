package cryptfs

// Benchmark go built-int GCM against spacemonkey openssl bindings
//
// Note: The benchmarks in this file supersede the ones in the openssl_benchmark
//       directory as they use the same code paths that gocryptfs actually uses.
//
// Run benchmark:
// go test -bench Enc

import (
	"crypto/aes"
	"testing"
)

func benchmarkGoEnc(b *testing.B, plaintext []byte, key []byte, nonce []byte) (ciphertext []byte) {
	b.SetBytes(int64(len(plaintext)))
	aes, err := aes.NewCipher(key[:])
	if err != nil {
		b.Fatal(err)
	}
	aesgcm, err := goGCMWrapper(aes, len(nonce))
	if err != nil {
		b.Fatal(err)
	}
	// This would be fileID + blockNo
	aData := make([]byte, 24)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encrypt plaintext and append to nonce
		ciphertext = aesgcm.Seal(nonce, nonce, plaintext, aData)
	}
	return ciphertext
}

func benchmarkOpensslEnc(b *testing.B, plaintext []byte, key []byte, nonce []byte) (ciphertext []byte) {
	b.SetBytes(int64(len(plaintext)))
	var aesgcm opensslGCM
	aesgcm.key = key
	// This would be fileID + blockNo
	aData := make([]byte, 24)
	for i := 0; i < b.N; i++ {
		// Encrypt plaintext and append to nonce
		ciphertext = aesgcm.Seal(nonce, nonce, plaintext, aData)
	}
	return ciphertext
}

func BenchmarkEnc_Go_4k_AES256_nonce96(b *testing.B) {
	plaintext := make([]byte, 4048)
	key := make([]byte, 256/8)
	nonce := make([]byte, 96/8)
	benchmarkGoEnc(b, plaintext, key, nonce)
}

func BenchmarkEnc_Go_4k_AES256_nonce128(b *testing.B) {
	plaintext := make([]byte, 4048)
	key := make([]byte, 256/8)
	nonce := make([]byte, 128/8)
	benchmarkGoEnc(b, plaintext, key, nonce)
}

func BenchmarkEnc_OpenSSL_4k_AES256_nonce96(b *testing.B) {
	plaintext := make([]byte, 4048)
	key := make([]byte, 256/8)
	nonce := make([]byte, 96/8)
	benchmarkOpensslEnc(b, plaintext, key, nonce)
}

func BenchmarkEnc_OpenSSL_4k_AES256_nonce128(b *testing.B) {
	plaintext := make([]byte, 4048)
	key := make([]byte, 256/8)
	nonce := make([]byte, 96/8)
	benchmarkOpensslEnc(b, plaintext, key, nonce)
}
