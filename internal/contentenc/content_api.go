package contentenc

import "github.com/rfjakob/gocryptfs/internal/cryptocore"

type ContentEnc struct {
	// Cryptographic primitives
	cryptoCore *cryptocore.CryptoCore
	// Plaintext block size
	plainBS     uint64
	// Ciphertext block size
	cipherBS    uint64
	// All-zero block of size cipherBS, for fast compares
	allZeroBlock []byte
}

func New(cc *cryptocore.CryptoCore, plainBS uint64) *ContentEnc {

	cipherBS := plainBS + uint64(cc.IVLen) + cryptocore.AuthTagLen

	return &ContentEnc{
		cryptoCore: cc,
		plainBS: plainBS,
		cipherBS: cipherBS,
		allZeroBlock: make([]byte, cipherBS),
	}
}


func (be *ContentEnc) PlainBS() uint64 {
	return be.plainBS
}
