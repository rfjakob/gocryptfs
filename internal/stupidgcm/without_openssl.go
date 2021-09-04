// +build without_openssl

package stupidgcm

import (
	"fmt"
	"os"

	"crypto/cipher"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

type StupidGCM struct{}

const (
	// BuiltWithoutOpenssl indicates if openssl been disabled at compile-time
	BuiltWithoutOpenssl = true
)

func errExit() {
	fmt.Fprintln(os.Stderr, "gocryptfs has been compiled without openssl support but you are still trying to use openssl")
	os.Exit(exitcodes.OpenSSL)
}

func New(_ []byte, _ bool) cipher.AEAD {
	errExit()
	return nil
}

func NewXchacha20poly1305(_ []byte) cipher.AEAD {
	errExit()
	return nil
}
