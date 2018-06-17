package readpassword

import (
	"os"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Trezor reads 16 deterministically derived bytes from a
// SatoshiLabs Trezor USB security module.
// The bytes are pseudorandom binary data and may contain null bytes.
// This function either succeeds and returns 16 bytes or calls os.Exit to end
// the application.
func Trezor() []byte {
	var err error
	// TODO try to read bytes here....
	// Handle errors
	if err != nil {
		tlog.Fatal.Printf("xxx some error was encountered...")
		os.Exit(exitcodes.TrezorError)
	}

	tlog.Warn.Println("XXX readpassword.Trezor(): not implemented yet - returning hardcoded dummy bytes XXX")
	return []byte("1234567890123456")
}
