package nametransform

import "github.com/rfjakob/gocryptfs/internal/cryptocore"

type NameTransform struct {
	cryptoCore *cryptocore.CryptoCore
	useEME     bool
	longNames  bool
	DirIVCache dirIVCache
}

func New(c *cryptocore.CryptoCore, useEME bool, longNames bool) *NameTransform {
	return &NameTransform{
		cryptoCore: c,
		longNames:  longNames,
		useEME:     useEME,
	}
}
