// Package nametransform encrypts and decrypts filenames.
package nametransform

import (
	"crypto/aes"
	"encoding/base64"
	"syscall"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// NameTransform is used to transform filenames.
type NameTransform struct {
	cryptoCore *cryptocore.CryptoCore
	longNames  bool
	DirIVCache dirIVCache
}

// New returns a new NameTransform instance.
func New(c *cryptocore.CryptoCore, longNames bool) *NameTransform {
	return &NameTransform{
		cryptoCore: c,
		longNames:  longNames,
	}
}

// DecryptName - decrypt base64-encoded encrypted filename "cipherName"
//
// This function is exported because it allows for a very efficient readdir
// implementation (read IV once, decrypt all names using this function).
func (n *NameTransform) DecryptName(cipherName string, iv []byte) (string, error) {
	bin, err := base64.URLEncoding.DecodeString(cipherName)
	if err != nil {
		return "", err
	}
	if len(bin)%aes.BlockSize != 0 {
		tlog.Debug.Printf("DecryptName %q: decoded length %d is not a multiple of 16", cipherName, len(bin))
		return "", syscall.EINVAL
	}
	bin = eme.Transform(n.cryptoCore.BlockCipher, iv, bin, eme.DirectionDecrypt)
	bin, err = unPad16(bin)
	if err != nil {
		tlog.Debug.Printf("pad16 error detail: %v", err)
		// unPad16 returns detailed errors including the position of the
		// incorrect bytes. Kill the padding oracle by lumping everything into
		// a generic error.
		return "", syscall.EINVAL
	}
	plain := string(bin)
	return plain, err
}

// EncryptName encrypts "plainName", returns a base64-encoded "cipherName64".
// Used internally by EncryptPathDirIV().
// The encryption is either CBC or EME, depending on "useEME".
//
// This function is exported because fusefrontend needs access to the full (not hashed)
// name if longname is used. Otherwise you should use EncryptPathDirIV()
func (n *NameTransform) EncryptName(plainName string, iv []byte) (cipherName64 string) {
	bin := []byte(plainName)
	bin = pad16(bin)
	bin = eme.Transform(n.cryptoCore.BlockCipher, iv, bin, eme.DirectionEncrypt)
	cipherName64 = base64.URLEncoding.EncodeToString(bin)
	return cipherName64
}
