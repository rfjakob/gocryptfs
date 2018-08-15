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
	// TrezorSupport is true when gocryptfs has been compile with -tags enable_trezor
	TrezorSupport = false
)

// Trezor determinitically derives 32 bytes from the payload and the connected
// USB security module.
func Trezor(payload []byte) []byte {
	tlog.Fatal.Printf("This binary has been compiled without Trezor support")
	os.Exit(1)
	return nil
}
