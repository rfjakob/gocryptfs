// +build !go1.5

package cryptfs

import (
	"crypto/cipher"
	"fmt"
)

// goGCMWrapper - This wrapper makes sure gocryptfs can be compiled on Go
// versions 1.4 and lower that lack NewGCMWithNonceSize().
// 128 bit GCM IVs will not work when using built-in Go crypto, obviously, when
// compiled on 1.4.
func goGCMWrapper(bc cipher.Block, nonceSize int) (cipher.AEAD, error) {
	if nonceSize != 12 {
		Warn.Printf("128 bit GCM IVs are not supported by Go 1.4 and lower.\n")
		Warn.Printf("Please use openssl crypto or recompile using a newer Go runtime.\n")
		return nil, fmt.Errorf("128 bit GCM IVs are not supported by Go 1.4 and lower")
	}
	return cipher.NewGCM(bc)
}
