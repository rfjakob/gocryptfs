// +build !enable_trezor

package readpassword

import (
	"os"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	TrezorPayloadLen = 32
)

func Trezor(payload []byte) []byte {
	tlog.Fatal.Printf("\"-trezor\" is not implemented yet.")
	os.Exit(1)
	return nil
}
