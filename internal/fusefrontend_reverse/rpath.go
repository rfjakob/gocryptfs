package fusefrontend_reverse

import (
	"path/filepath"
	"strings"
)

func (fs *FS) abs(relPath string, err error) (string, error) {
	if err != nil {
		return "", err
	}
	return filepath.Join(fs.args.Cipherdir, relPath), nil
}

const (
	ENCRYPT = iota
	DECRYPT
)

func (fs *FS) encryptPath(relPath string) (string, error) {
	return fs.transformPath(relPath, ENCRYPT)
}

func (fs *FS) decryptPath(relPath string) (string, error) {
	return fs.transformPath(relPath, DECRYPT)
}

func (fs *FS) transformPath(relPath string, direction int) (string, error) {
	if fs.args.PlaintextNames {
		return relPath, nil
	}
	var err error
	var transformedParts []string
	iv := make([]byte, 16)
	parts := strings.Split(relPath, "/")
	for _, part := range parts {
		var transformedPart string
		switch direction {
		case ENCRYPT:
			transformedPart = fs.nameTransform.EncryptName(part, iv)
		case DECRYPT:
			transformedPart, err = fs.nameTransform.DecryptName(part, iv)
			if err != nil {
				return "", err
			}
		default:
			panic("bug: invalid direction value")
		}
		transformedParts = append(transformedParts, transformedPart)
	}
	return filepath.Join(transformedParts...), nil
}

func (fs *FS) isFiltered(relPath string) bool {
	return false
}
