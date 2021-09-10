package speed

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/rfjakob/gocryptfs/v2/internal/siv_aead"
	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
)

/*
Make the "-speed" benchmarks also accessible to the standard test system.
Example run:

$ go test -bench .
BenchmarkStupidGCM-2   	  100000	     22552 ns/op	 181.62 MB/s
BenchmarkGoGCM-2       	   20000	     81871 ns/op	  50.03 MB/s
BenchmarkAESSIV-2      	   10000	    104623 ns/op	  39.15 MB/s
PASS
ok  	github.com/rfjakob/gocryptfs/v2/internal/speed	6.022s
*/

func BenchmarkStupidGCM(b *testing.B) {
	bStupidGCM(b)
}

func BenchmarkStupidGCMDecrypt(b *testing.B) {
	if stupidgcm.BuiltWithoutOpenssl {
		b.Skip("openssl has been disabled at compile-time")
	}
	bDecrypt(b, stupidgcm.NewAES256GCM(randBytes(32)))
}

func BenchmarkGoGCM(b *testing.B) {
	bGoGCM(b)
}

func BenchmarkGoGCMDecrypt(b *testing.B) {
	gAES, err := aes.NewCipher(randBytes(32))
	if err != nil {
		b.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		b.Fatal(err)
	}
	bDecrypt(b, gGCM)
}

func BenchmarkAESSIV(b *testing.B) {
	bAESSIV(b)
}

func BenchmarkAESSIVDecrypt(b *testing.B) {
	bEncrypt(b, siv_aead.New(randBytes(64)))
}

func BenchmarkXchacha(b *testing.B) {
	bXchacha20poly1305(b)
}

func BenchmarkXchachaDecrypt(b *testing.B) {
	c, _ := chacha20poly1305.NewX(randBytes(32))
	bDecrypt(b, c)
}

func BenchmarkStupidXchacha(b *testing.B) {
	bStupidXchacha(b)
}

func BenchmarkStupidXchachaDecrypt(b *testing.B) {
	bDecrypt(b, stupidgcm.NewXchacha20poly1305(randBytes(32)))
}

func BenchmarkStupidChacha(b *testing.B) {
	bEncrypt(b, stupidgcm.NewChacha20poly1305(randBytes(32)))
}

func BenchmarkStupidChachaDecrypt(b *testing.B) {
	bDecrypt(b, stupidgcm.NewChacha20poly1305(randBytes(32)))
}
