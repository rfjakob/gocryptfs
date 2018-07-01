// +build !enable_trezor

package readpassword

import (
	"os"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// TrezorPayloadLen is the length of the payload data passed to Trezor's
	// CipherKeyValue function.
	TrezorPayloadLen = 32
)

// Trezor determinitically derives 32 bytes from the payload and the connected
// USB security module.
func Trezor(payload []byte) []byte {
	tlog.Fatal.Printf("\"-trezor\" is not implemented yet.")
	os.Exit(1)
	return nil
}
