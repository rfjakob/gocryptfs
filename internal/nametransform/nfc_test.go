package nametransform

import (
	"strconv"
	"testing"

	"golang.org/x/text/unicode/norm"
)

func TestNFD2NFC(t *testing.T) {
	n := newLognamesTestInstance(NameMax)
	n.nfd2nfc = true
	iv := make([]byte, DirIVLen)
	srcNFC := "Österreich Café"
	srcNFD := norm.NFD.String(srcNFC)

	// cipherName should get normalized to NFC
	cipherName, _ := n.EncryptName(srcNFD, iv)
	// Decrypt without changing normalization
	decryptedRaw, _ := n.decryptName(cipherName, iv)
	if srcNFC != decryptedRaw {
		t.Errorf("want %s have %s", strconv.QuoteToASCII(srcNFC), strconv.QuoteToASCII(decryptedRaw))
	}
	// Decrypt with normalizing to NFD
	decrypted, _ := n.DecryptName(cipherName, iv)
	if srcNFD != decrypted {
		t.Errorf("want %s have %s", strconv.QuoteToASCII(srcNFD), strconv.QuoteToASCII(decrypted))
	}
}
