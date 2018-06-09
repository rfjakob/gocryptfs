// +build darwin
package trezor

import (
	"log"
)

func (trezor *trezor) Reconnect() {
	log.Panic("Trezor is not supported on this platform :(")
}

