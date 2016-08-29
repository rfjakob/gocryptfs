package fusefrontend_reverse

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
)

var zeroDirIV []byte

func init() {
	zeroDirIV = make([]byte, 16)
}

func (rfs *reverseFS) abs(relPath string, err error) (string, error) {
	if err != nil {
		return "", err
	}
	return filepath.Join(rfs.args.Cipherdir, relPath), nil
}

const (
	ENCRYPT = iota
	DECRYPT
)

func (rfs *reverseFS) encryptPath(relPath string) (string, error) {
	return rfs.transformPath(relPath, ENCRYPT)
}

func (rfs *reverseFS) decryptPath(relPath string) (string, error) {
	return rfs.transformPath(relPath, DECRYPT)
}

func (rfs *reverseFS) transformPath(relPath string, direction int) (string, error) {
	if rfs.args.PlaintextNames || relPath == "" {
		return relPath, nil
	}
	var err error
	var transformedParts []string
	parts := strings.Split(relPath, "/")
	for _, part := range parts {
		var transformedPart string
		switch direction {
		case ENCRYPT:
			transformedPart = rfs.nameTransform.EncryptName(part, zeroDirIV)
		case DECRYPT:
			transformedPart, err = rfs.nameTransform.DecryptName(part, zeroDirIV)
			if err != nil {
				// We get lots of decrypt requests for names like ".Trash" that
				// are invalid base64. Convert them to ENOENT so the correct
				// error gets returned to the user.
				if _, ok := err.(base64.CorruptInputError); ok {
					fmt.Printf("converting to ENOENT\n")
					return "", syscall.ENOENT
				}
				return "", err
			}
		default:
			panic("bug: invalid direction value")
		}
		transformedParts = append(transformedParts, transformedPart)
	}
	return filepath.Join(transformedParts...), nil
}

func (rfs *reverseFS) isFiltered(relPath string) bool {
	return false
}
