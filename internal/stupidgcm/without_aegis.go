//go:build without_aegis || !cgo
// +build without_aegis !cgo

package stupidgcm

import (
	"fmt"
	"os"

	"crypto/cipher"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

const (
	// BuiltWithoutAegis indicates if openssl been disabled at compile-time
	BuiltWithoutAegis = true
)

type stupidAegis struct {
	aead cipher.AEAD
}

func NewAegis(_ []byte) cipher.AEAD {
	fmt.Fprintln(os.Stderr, "I have been compiled without aegis support but you are still trying to use aegis")
	os.Exit(exitcodes.Aegis)
	return nil
}
