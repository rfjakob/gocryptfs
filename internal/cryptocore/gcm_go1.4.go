// +build !go1.5
// = go 1.4 or lower

package cryptocore

import (
	"crypto/cipher"
	"fmt"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// HaveModernGoGCM indicates if Go GCM supports 128-bit nonces
	HaveModernGoGCM = false
)

// goGCMWrapper - This wrapper makes sure gocryptfs can be compiled on Go
// versions 1.4 and lower that lack NewGCMWithNonceSize().
// 128 bit GCM IVs will not work when using built-in Go crypto, obviously, when
// compiled on 1.4.
func goGCMWrapper(bc cipher.Block, nonceSize int) (cipher.AEAD, error) {
	if nonceSize != 12 {
		tlog.Warn.Printf("128 bit GCM IVs are not supported by Go 1.4 and lower.")
		tlog.Warn.Printf("Please use openssl crypto or recompile using a newer Go runtime.")
		return nil, fmt.Errorf("128 bit GCM IVs are not supported by Go 1.4 and lower")
	}
	return cipher.NewGCM(bc)
}
