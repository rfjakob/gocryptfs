// +build without_openssl

package stupidgcm

import (
	"fmt"
	"os"
)

type stupidGCM struct{}

const (
	// BuiltWithoutOpenssl indicates if openssl been disabled at compile-time
	BuiltWithoutOpenssl = true
)

//authentication error - needed to compile as same varaible is exported when openssl is enable via stupidgcm.go
var AuthError error = fmt.Errorf("stupidgcm: message authentication failed with openssl disabled!")

func errExit() {
	fmt.Fprintln(os.Stderr, "gocryptfs has been compiled without openssl support but you are still trying to use openssl")
	os.Exit(2)
}

func New(_ []byte, _ bool) stupidGCM {
	errExit()
	// Never reached
	return stupidGCM{}
}

func (g stupidGCM) NonceSize() int {
	errExit()
	return -1
}

func (g stupidGCM) Overhead() int {
	errExit()
	return -1
}

func (g stupidGCM) Seal(_, _, _, _ []byte) []byte {
	errExit()
	return nil
}

func (g stupidGCM) Open(_, _, _, _ []byte) ([]byte, error) {
	errExit()
	return nil, nil
}
