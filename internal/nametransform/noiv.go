package nametransform

import (
	"strings"
)

const (
	OpEncrypt = iota
	OpDecrypt
)

// DecryptPathNoIV - decrypt path using CBC without any IV.
// This function is deprecated by the the more secure DirIV variant and only retained
// for compatability with old filesystems.
func (be *NameTransform) DecryptPathNoIV(cipherPath string) (plainPath string, err error) {
	plainPath, err = be.translatePathNoIV(cipherPath, OpDecrypt)
	return plainPath, err
}

// EncryptPathNoIV - decrypt path using CBC without any IV.
// This function is deprecated by the the more secure DirIV variant and only retained
// for compatability with old filesystems.
func (be *NameTransform) EncryptPathNoIV(plainPath string) (cipherPath string) {
	cipherPath, _ = be.translatePathNoIV(plainPath, OpEncrypt)
	return cipherPath
}

// translatePathZeroIV - encrypt or decrypt path using CBC with an all-zero IV.
// Just splits the string on "/" and hands the parts to encryptName() / decryptName()
func (be *NameTransform) translatePathNoIV(path string, op int) (string, error) {
	var err error

	// Empty string means root directory
	if path == "" {
		return path, err
	}

	zeroIV := make([]byte, dirIVLen)

	// Run operation on each path component
	var translatedParts []string
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" {
			// This happens on "/foo/bar/" on the front and on the end.
			// Don't panic.
			translatedParts = append(translatedParts, "")
			continue
		}
		var newPart string
		if op == OpEncrypt {
			newPart = be.EncryptName(part, zeroIV)
		} else {
			newPart, err = be.DecryptName(part, zeroIV)
			if err != nil {
				return "", err
			}
		}
		translatedParts = append(translatedParts, newPart)
	}

	return strings.Join(translatedParts, "/"), err
}
