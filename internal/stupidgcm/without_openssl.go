// +build without_openssl

package stupidgcm

import (
	"fmt"
	"os"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
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

func New(_ []byte, _ bool) *StupidGCM {
	errExit()
	// Never reached
	return &StupidGCM{}
}

func (g *StupidGCM) NonceSize() int {
	errExit()
	return -1
}

func (g *StupidGCM) Overhead() int {
	errExit()
	return -1
}

func (g *StupidGCM) Seal(_, _, _, _ []byte) []byte {
	errExit()
	return nil
}

func (g *StupidGCM) Open(_, _, _, _ []byte) ([]byte, error) {
	errExit()
	return nil, nil
}

func (g *StupidGCM) Wipe() {
	errExit()
}
