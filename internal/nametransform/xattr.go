package nametransform

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// xattr names are encrypted like file names, but with a fixed IV.
// Padded with "_xx" for length 16.
var xattrNameIV = []byte("xattr_name_iv_xx")

func isValidXattrName(name string) error {
	if name == "" {
		return fmt.Errorf("empty input")
	}
	if strings.Contains(name, "\000") {
		return fmt.Errorf("contains forbidden null byte")
	}
	return nil
}

// EncryptXattrName encrypts an extended attribute (xattr) name.
// xattr names are encrypted like file names, but with a fixed IV, and fewer
// naming restriction.
func (n *NameTransform) EncryptXattrName(plainName string) (cipherName64 string, err error) {
	if err := isValidXattrName(plainName); err != nil {
		tlog.Warn.Printf("EncryptXattrName %q: invalid plainName: %v", plainName, err)
		return "", syscall.EBADMSG
	}
	return n.encryptName(plainName, xattrNameIV), nil
}

// DecryptXattrName calls decryptName to try and decrypt a base64-encoded encrypted
// filename "cipherName", and failing that checks if it can be bypassed
func (n *NameTransform) DecryptXattrName(cipherName string) (plainName string, err error) {
	if plainName, err = n.decryptName(cipherName, xattrNameIV); err != nil {
		return "", err
	}
	if err := isValidXattrName(plainName); err != nil {
		tlog.Warn.Printf("DecryptXattrName %q: invalid name after decryption: %v", cipherName, err)
		return "", syscall.EBADMSG
	}
	return plainName, err
}
