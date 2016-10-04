// +build without_openssl

package stupidgcm

import (
	"os"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

type stupidGCM struct{}

const (
	// BuiltWithoutOpenssl indicates if openssl been disabled at compile-time
	BuiltWithoutOpenssl = true
)

func errExit() {
	tlog.Fatal.Println("gocryptfs has been compiled without openssl support but you are still trying to use openssl")
	os.Exit(2)
}

func New(_ []byte) stupidGCM {
	errExit()
	// This panic is never reached, but having it here stops the Go compiler
	// from complaining about the missing return code.
	panic("")
}

func (g stupidGCM) NonceSize() int {
	errExit()
	panic("")
}

func (g stupidGCM) Overhead() int {
	errExit()
	panic("")
}

func (g stupidGCM) Seal(_, _, _, _ []byte) []byte {
	errExit()
	panic("")
}

func (g stupidGCM) Open(_, _, _, _ []byte) ([]byte, error) {
	errExit()
	panic("")
}
