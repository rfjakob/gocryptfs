// Package stupidgcm wraps OpenSSL to provide a cipher.AEAD interface for
// authenticated encryption algorithms.
//
// The supported algorithms are:
//
// (1) AES-GCM-256 (OpenSSL EVP_aes_256_gcm)
//
// (2) ChaCha20-Poly1305 (OpenSSL EVP_chacha20_poly1305)
//
// (3) XChaCha20-Poly1305 (OpenSSL EVP_chacha20_poly1305 + Go HChaCha20)
//
// The golang.org/x/crypto libraries provides implementations for all algorithms,
// and the test suite verifies that the implementation in this package gives
// the exact same results.
//
// However, OpenSSL has optimized assembly for almost all platforms, which Go
// does not. Example for a 32-bit ARM device (Odroid XU4):
//
//   $ gocrypts -speed
//   gocryptfs v2.1-68-gedf9d4c.stupidchacha; go-fuse v2.1.1-0.20210825171523-3ab5d95a30ae; 2021-09-04 go1.16.7 linux/arm
//   AES-GCM-256-OpenSSL               56.84 MB/s    (selected in auto mode)
//   AES-GCM-256-Go                    16.61 MB/s
//   AES-SIV-512-Go                    16.49 MB/s
//   XChaCha20-Poly1305-Go             39.08 MB/s    (use via -xchacha flag)
//   XChaCha20-Poly1305-OpenSSL       141.82 MB/s
//
// This package is "stupid" in the sense that it only supports a narrow set of
// key- and iv-lengths, and panics if it does not like what you pass it.
// See the constructor functions for which restrictions apply for each algorithm.
// Also, it is only tested for block lengths up to 5000 bytes, because this is
// what gocryptfs uses.
//
// Corrupt ciphertexts never cause a panic. Instead, ErrAuth is returned on
// decryption.
//
// XChaCha20-Poly1305
//
// The XChaCha20-Poly1305 implementation is more complicated than the others,
// because OpenSSL does not support XChaCha20-Poly1305 directly. Follow
// https://github.com/openssl/openssl/issues/5523 to get notified when it is
// accepted into OpenSSL.
//
// Fortunately, XChaCha20-Poly1305 is just ChaCha20-Poly1305 with some key+iv
// mixing using HChaCha20 in front:
//
//     key (32 bytes), iv (24 bytes)
//      |
//      v
//     HChaCha20 (provided by golang.org/x/crypto/chacha20)
//      |
//      v
//     key2 (32 bytes), iv2 (16 bytes)
//      |
//      v
//     ChaCha20-Poly1305 (OpenSSL EVP_chacha20_poly1305)
//
// As HChaCha20 is very fast, XChaCha20-Poly1305 gets almost the same throughput
// as ChaCha20-Poly1305 (for 4kiB blocks).
package stupidgcm
