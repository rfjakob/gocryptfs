package fusefrontend_reverse

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"syscall"
)

func (rfs *reverseFS) abs(relPath string, err error) (string, error) {
	if err != nil {
		return "", err
	}
	return filepath.Join(rfs.args.Cipherdir, relPath), nil
}

func (rfs *reverseFS) decryptPath(relPath string) (string, error) {
	if rfs.args.PlaintextNames || relPath == "" {
		return relPath, nil
	}
	var err error
	var transformedParts []string
	parts := strings.Split(relPath, "/")
	for i, part := range parts {
		var transformedPart string
		dirIV := deriveDirIV(filepath.Join(parts[:i]...))
		transformedPart, err = rfs.nameTransform.DecryptName(part, dirIV)
		if err != nil {
			// We get lots of decrypt requests for names like ".Trash" that
			// are invalid base64. Convert them to ENOENT so the correct
			// error gets returned to the user.
			if _, ok := err.(base64.CorruptInputError); ok {
				return "", syscall.ENOENT
			}
			return "", err
		}
		transformedParts = append(transformedParts, transformedPart)
	}
	return filepath.Join(transformedParts...), nil
}

func (rfs *reverseFS) isFiltered(relPath string) bool {
	return false
}
