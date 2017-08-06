// Package nametransform encrypts and decrypts filenames.
package nametransform

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"syscall"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/internal/nametransform/dirivcache"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// NameTransform is used to transform filenames.
type NameTransform struct {
	emeCipher  *eme.EMECipher
	longNames  bool
	DirIVCache dirivcache.DirIVCache
	// B64 = either base64.URLEncoding or base64.RawURLEncoding, depeding
	// on the Raw64 feature flag
	B64 *base64.Encoding
}

// New returns a new NameTransform instance.
func New(e *eme.EMECipher, longNames bool, raw64 bool) *NameTransform {
	b64 := base64.URLEncoding
	if raw64 {
		b64 = base64.RawURLEncoding
	}
	return &NameTransform{
		emeCipher: e,
		longNames: longNames,
		B64:       b64,
	}
}

// DecryptName decrypts a base64-encoded encrypted filename "cipherName" using the
// initialization vector "iv".
func (n *NameTransform) DecryptName(cipherName string, iv []byte) (string, error) {
	bin, err := n.B64.DecodeString(cipherName)
	if err != nil {
		return "", err
	}
	if len(bin) == 0 {
		tlog.Warn.Printf("DecryptName: empty input")
		return "", syscall.EBADMSG
	}
	if len(bin)%aes.BlockSize != 0 {
		tlog.Debug.Printf("DecryptName %q: decoded length %d is not a multiple of 16", cipherName, len(bin))
		return "", syscall.EBADMSG
	}
	bin = n.emeCipher.Decrypt(iv, bin)
	bin, err = unPad16(bin)
	if err != nil {
		tlog.Debug.Printf("DecryptName: unPad16 error detail: %v", err)
		// unPad16 returns detailed errors including the position of the
		// incorrect bytes. Kill the padding oracle by lumping everything into
		// a generic error.
		return "", syscall.EBADMSG
	}
	// A name can never contain a null byte or "/". Make sure we never return those
	// to the kernel, even when we read a corrupted (or fuzzed) filesystem.
	if bytes.Contains(bin, []byte{0}) || bytes.Contains(bin, []byte("/")) {
		return "", syscall.EBADMSG
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
	bin = n.emeCipher.Encrypt(iv, bin)
	cipherName64 = n.B64.EncodeToString(bin)
	return cipherName64
}
