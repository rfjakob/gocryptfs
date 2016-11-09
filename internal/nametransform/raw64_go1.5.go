//+build go1.5

package nametransform

import (
	"encoding/base64"
)

const (
	// HaveRaw64 is true when Go is new enough to have base64.RawURLEncoding
	HaveRaw64 = true
)

func getRaw64Encoding() *base64.Encoding {
	return base64.RawURLEncoding
}
