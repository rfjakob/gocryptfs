//+build go1.5

package nametransform

import (
	"encoding/base64"
)

const (
	HaveRaw64 = true
)

func getRaw64Encoding() *base64.Encoding {
	return base64.RawURLEncoding
}
