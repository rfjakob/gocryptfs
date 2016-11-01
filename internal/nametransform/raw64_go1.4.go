//+build !go1.5

package nametransform

import (
	"encoding/base64"
	"log"
)

const (
	HaveRaw64 = false
)

func getRaw64Encoding() *base64.Encoding {
	log.Panicf("Tried to use base64.RawURLEncoding but your Go version does not provide it.\n" +
		"You need Go 1.5 or higher.")
	return nil
}
