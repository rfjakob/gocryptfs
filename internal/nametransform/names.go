// Package nametransform encrypts and decrypts filenames.
package nametransform

import (
	"crypto/aes"
	"encoding/base64"
	"math"
	"path/filepath"
	"syscall"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// Like ext4, we allow at most 255 bytes for a file name.
	NameMax = 255
)

// NameTransform is used to transform filenames.
type NameTransform struct {
	emeCipher *eme.EMECipher
	// Names longer than `longNameMax` are hashed. Set to MaxInt when
	// longnames are disabled.
	longNameMax int
	// B64 = either base64.URLEncoding or base64.RawURLEncoding, depending
	// on the Raw64 feature flag
	B64 *base64.Encoding
	// Patterns to bypass decryption
	badnamePatterns    []string
	deterministicNames bool
}

// New returns a new NameTransform instance.
//
// If `longNames` is set, names longer than `longNameMax` are hashed to
// `gocryptfs.longname.[sha256]`.
// Pass `longNameMax = 0` to use the default value (255).
func New(e *eme.EMECipher, longNames bool, longNameMax uint8, raw64 bool, badname []string, deterministicNames bool) *NameTransform {
	tlog.Debug.Printf("nametransform.New: longNameMax=%v, raw64=%v, badname=%q",
		longNameMax, raw64, badname)
	b64 := base64.URLEncoding
	if raw64 {
		b64 = base64.RawURLEncoding
	}
	var effectiveLongNameMax int = math.MaxInt32
	if longNames {
		if longNameMax == 0 {
			effectiveLongNameMax = NameMax
		} else {
			effectiveLongNameMax = int(longNameMax)
		}
	}
	return &NameTransform{
		emeCipher:          e,
		longNameMax:        effectiveLongNameMax,
		B64:                b64,
		badnamePatterns:    badname,
		deterministicNames: deterministicNames,
	}
}

// DecryptName calls decryptName to try and decrypt a base64-encoded encrypted
// filename "cipherName", and failing that checks if it can be bypassed
func (n *NameTransform) DecryptName(cipherName string, iv []byte) (string, error) {
	res, err := n.decryptName(cipherName, iv)
	if err != nil && n.HaveBadnamePatterns() {
		res, err = n.decryptBadname(cipherName, iv)
	}
	if err != nil {
		return "", err
	}
	if err := IsValidName(res); err != nil {
		tlog.Warn.Printf("DecryptName %q: invalid name after decryption: %v", cipherName, err)
		return "", syscall.EBADMSG
	}
	return res, err
}

// decryptName decrypts a base64-encoded encrypted filename "cipherName" using the
// initialization vector "iv".
func (n *NameTransform) decryptName(cipherName string, iv []byte) (string, error) {
	bin, err := n.B64.DecodeString(cipherName)
	if err != nil {
		return "", err
	}
	if len(bin) == 0 {
		tlog.Warn.Printf("decryptName: empty input")
		return "", syscall.EBADMSG
	}
	if len(bin)%aes.BlockSize != 0 {
		tlog.Debug.Printf("decryptName %q: decoded length %d is not a multiple of 16", cipherName, len(bin))
		return "", syscall.EBADMSG
	}
	bin = n.emeCipher.Decrypt(iv, bin)
	bin, err = unPad16(bin)
	if err != nil {
		tlog.Warn.Printf("decryptName %q: unPad16 error: %v", cipherName, err)
		return "", syscall.EBADMSG
	}
	plain := string(bin)
	return plain, err
}

// EncryptName encrypts a file name "plainName" and returns a base64-encoded "cipherName64",
// encrypted using EME (https://github.com/rfjakob/eme).
//
// plainName is checked for null bytes, slashes etc. and such names are rejected
// with an error.
//
// This function is exported because in some cases, fusefrontend needs access
// to the full (not hashed) name if longname is used.
func (n *NameTransform) EncryptName(plainName string, iv []byte) (cipherName64 string, err error) {
	if err := IsValidName(plainName); err != nil {
		tlog.Warn.Printf("EncryptName %q: invalid plainName: %v", plainName, err)
		return "", syscall.EBADMSG
	}
	return n.encryptName(plainName, iv), nil
}

// encryptName encrypts "plainName" and returns a base64-encoded "cipherName64",
// encrypted using EME (https://github.com/rfjakob/eme).
//
// No checks for null bytes etc are performed against plainName.
func (n *NameTransform) encryptName(plainName string, iv []byte) (cipherName64 string) {
	bin := []byte(plainName)
	bin = pad16(bin)
	bin = n.emeCipher.Encrypt(iv, bin)
	cipherName64 = n.B64.EncodeToString(bin)
	return cipherName64
}

// EncryptAndHashName encrypts "name" and hashes it to a longname if it is
// too long.
// Returns ENAMETOOLONG if "name" is longer than 255 bytes.
func (be *NameTransform) EncryptAndHashName(name string, iv []byte) (string, error) {
	// Prevent the user from creating files longer than 255 chars.
	if len(name) > NameMax {
		return "", syscall.ENAMETOOLONG
	}
	cName, err := be.EncryptName(name, iv)
	if err != nil {
		return "", err
	}
	if len(cName) > be.longNameMax {
		return be.HashLongName(cName), nil
	}
	return cName, nil
}

// B64EncodeToString returns a Base64-encoded string
func (n *NameTransform) B64EncodeToString(src []byte) string {
	return n.B64.EncodeToString(src)
}

// B64DecodeString decodes a Base64-encoded string
func (n *NameTransform) B64DecodeString(s string) ([]byte, error) {
	return n.B64.DecodeString(s)
}

// Dir is like filepath.Dir but returns "" instead of ".".
func Dir(path string) string {
	d := filepath.Dir(path)
	if d == "." {
		return ""
	}
	return d
}

// GetLongNameMax will return curent `longNameMax`. File name longer than
// this should be hashed.
func (n *NameTransform) GetLongNameMax() int {
	return n.longNameMax
}
