package nametransform

import "github.com/rfjakob/gocryptfs/internal/cryptocore"

type NameTransform struct {
	cryptoCore *cryptocore.CryptoCore
	useEME     bool
	DirIVCache dirIVCache
}

func New(c *cryptocore.CryptoCore, useEME bool) *NameTransform {
	return &NameTransform{
		cryptoCore: c,
		useEME:     useEME,
	}
}
