// Package speed implements the "-speed" command-line option,
// similar to "openssl speed".
// It benchmarks the crypto algorithms and libraries used by
// gocryptfs.
package speed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/rfjakob/gocryptfs/internal/siv_aead"
	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
)

// 128-bit file ID + 64 bit block number = 192 bits = 24 bytes
const adLen = 24

// gocryptfs uses fixed-size 4 kiB blocks
const blockSize = 4096

// Run - run the speed the test and print the results.
func Run() {
	bTable := []struct {
		name      string
		f         func(*testing.B)
		preferred bool
	}{
		{name: "AES-GCM-256-OpenSSL", f: bStupidGCM, preferred: stupidgcm.PreferOpenSSL()},
		{name: "AES-GCM-256-Go", f: bGoGCM, preferred: !stupidgcm.PreferOpenSSL()},
		{name: "AES-SIV-512-Go", f: bAESSIV, preferred: false},
		{name: "XChaCha20-Poly1305-Go", f: bChacha20poly1305, preferred: false},
	}
	for _, b := range bTable {
		fmt.Printf("%-20s\t", b.name)
		mbs := mbPerSec(testing.Benchmark(b.f))
		if mbs > 0 {
			fmt.Printf("%7.2f MB/s", mbs)
		} else {
			fmt.Printf("    N/A")
		}
		if b.preferred {
			fmt.Printf("\t(selected in auto mode)\n")
		} else if b.name == "XChaCha20-Poly1305-Go" {
			fmt.Printf("\t(benchmark only, not selectable yet)\n")
		} else {
			fmt.Printf("\t\n")
		}
	}
}

func mbPerSec(r testing.BenchmarkResult) float64 {
	if r.Bytes <= 0 || r.T <= 0 || r.N <= 0 {
		return 0
	}
	return (float64(r.Bytes) * float64(r.N) / 1e6) / r.T.Seconds()
}

// Get "n" random bytes from /dev/urandom or panic
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

// bStupidGCM benchmarks stupidgcm's openssl GCM
func bStupidGCM(b *testing.B) {
	if stupidgcm.BuiltWithoutOpenssl {
		b.Skip("openssl has been disabled at compile-time")
	}
	key := randBytes(32)
	authData := randBytes(adLen)
	iv := randBytes(16)
	in := make([]byte, blockSize)
	b.SetBytes(int64(len(in)))

	sGCM := stupidgcm.New(key, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encrypt and append to nonce
		sGCM.Seal(iv, iv, in, authData)
	}
}

// bGoGCM benchmarks Go stdlib GCM
func bGoGCM(b *testing.B) {
	key := randBytes(32)
	authData := randBytes(adLen)
	iv := randBytes(16)
	in := make([]byte, blockSize)
	b.SetBytes(int64(len(in)))

	gAES, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encrypt and append to nonce
		gGCM.Seal(iv, iv, in, authData)
	}
}

// bAESSIV benchmarks AES-SIV from github.com/jacobsa/crypto/siv
func bAESSIV(b *testing.B) {
	key := randBytes(64)
	authData := randBytes(adLen)
	iv := randBytes(16)
	in := make([]byte, blockSize)
	b.SetBytes(int64(len(in)))
	gGCM := siv_aead.New(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encrypt and append to nonce
		gGCM.Seal(iv, iv, in, authData)
	}
}

// bChacha20poly1305 benchmarks XChaCha20 from golang.org/x/crypto/chacha20poly1305
func bChacha20poly1305(b *testing.B) {
	key := randBytes(32)
	authData := randBytes(adLen)
	iv := randBytes(chacha20poly1305.NonceSizeX)
	in := make([]byte, blockSize)
	b.SetBytes(int64(len(in)))
	c, _ := chacha20poly1305.NewX(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encrypt and append to nonce
		c.Seal(iv, iv, in, authData)
	}
}
