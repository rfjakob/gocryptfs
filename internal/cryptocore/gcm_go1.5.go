// +build go1.5
// = go 1.5 or higher

package cryptocore

import (
	"crypto/cipher"
)

const (
	// HaveModernGoGCM indicates if Go GCM supports 128-bit nonces
	HaveModernGoGCM = true
)

// goGCMWrapper - This wrapper makes sure gocryptfs can be compiled on Go
// versions 1.4 and lower that lack NewGCMWithNonceSize().
// 128 bit GCM IVs will not work when using built-in Go crypto, obviously, when
// compiled on 1.4.
func goGCMWrapper(bc cipher.Block, nonceSize int) (cipher.AEAD, error) {
	return cipher.NewGCMWithNonceSize(bc, nonceSize)
}
