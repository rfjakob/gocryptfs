// +build without_openssl

package stupidgcm

import (
	"fmt"
	"os"

	"crypto/cipher"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

const (
	// BuiltWithoutOpenssl indicates if openssl been disabled at compile-time
	BuiltWithoutOpenssl = true
)

func errExit() {
	fmt.Fprintln(os.Stderr, "I have been compiled without openssl support but you are still trying to use openssl")
	os.Exit(exitcodes.OpenSSL)
}

func NewAES256GCM(_ []byte) cipher.AEAD {
	errExit()
	return nil
}

func NewChacha20poly1305(_ []byte) cipher.AEAD {
	errExit()
	return nil
}

func NewXchacha20poly1305(_ []byte) cipher.AEAD {
	errExit()
	return nil
}
