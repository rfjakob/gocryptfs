package nametransform

// Filename encryption / decryption functions

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	"github.com/rfjakob/eme"
)

// DecryptName - decrypt base64-encoded encrypted filename "cipherName"
// The used encryption is either CBC or EME, depending on "useEME".
//
// This function is exported because it allows for a very efficient readdir
// implementation (read IV once, decrypt all names using this function).
func (n *NameTransform) DecryptName(cipherName string, iv []byte) (string, error) {

	bin, err := base64.URLEncoding.DecodeString(cipherName)
	if err != nil {
		return "", err
	}

	if len(bin)%aes.BlockSize != 0 {
		return "", fmt.Errorf("Decoded length %d is not a multiple of the AES block size", len(bin))
	}

	if n.useEME {
		bin = eme.Transform(n.cryptoCore.BlockCipher, iv, bin, eme.DirectionDecrypt)
	} else {
		cbc := cipher.NewCBCDecrypter(n.cryptoCore.BlockCipher, iv)
		cbc.CryptBlocks(bin, bin)
	}

	bin, err = unPad16(bin)
	if err != nil {
		return "", err
	}

	plain := string(bin)
	return plain, err
}

// encryptName - encrypt "plainName", return base64-encoded "cipherName64"
// The used encryption is either CBC or EME, depending on "useEME".
//
// This function is exported because fusefrontend needs access to the full (not hashed)
// name if longname is used
func (n *NameTransform) EncryptName(plainName string, iv []byte) (cipherName64 string) {

	bin := []byte(plainName)
	bin = pad16(bin)

	if n.useEME {
		bin = eme.Transform(n.cryptoCore.BlockCipher, iv, bin, eme.DirectionEncrypt)
	} else {
		cbc := cipher.NewCBCEncrypter(n.cryptoCore.BlockCipher, iv)
		cbc.CryptBlocks(bin, bin)
	}

	cipherName64 = base64.URLEncoding.EncodeToString(bin)
	return cipherName64
}
