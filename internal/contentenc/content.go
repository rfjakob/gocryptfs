// Package contentenc encrypts and decrypts file blocks.
package contentenc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// Default plaintext block size
	DefaultBS = 4096
)

type ContentEnc struct {
	// Cryptographic primitives
	cryptoCore *cryptocore.CryptoCore
	// Plaintext block size
	plainBS uint64
	// Ciphertext block size
	cipherBS uint64
	// All-zero block of size cipherBS, for fast compares
	allZeroBlock []byte
}

func New(cc *cryptocore.CryptoCore, plainBS uint64) *ContentEnc {

	cipherBS := plainBS + uint64(cc.IVLen) + cryptocore.AuthTagLen

	return &ContentEnc{
		cryptoCore:   cc,
		plainBS:      plainBS,
		cipherBS:     cipherBS,
		allZeroBlock: make([]byte, cipherBS),
	}
}

// PlainBS returns the plaintext block size
func (be *ContentEnc) PlainBS() uint64 {
	return be.plainBS
}

// CipherBS returns the ciphertext block size
func (be *ContentEnc) CipherBS() uint64 {
	return be.cipherBS
}

// DecryptBlocks - Decrypt a number of blocks
// TODO refactor to three-param for
func (be *ContentEnc) DecryptBlocks(ciphertext []byte, firstBlockNo uint64, fileId []byte) ([]byte, error) {
	cBuf := bytes.NewBuffer(ciphertext)
	var err error
	var pBuf bytes.Buffer
	for cBuf.Len() > 0 {
		cBlock := cBuf.Next(int(be.cipherBS))
		var pBlock []byte
		pBlock, err = be.DecryptBlock(cBlock, firstBlockNo, fileId)
		if err != nil {
			break
		}
		pBuf.Write(pBlock)
		firstBlockNo++
	}
	return pBuf.Bytes(), err
}

// DecryptBlock - Verify and decrypt GCM block
//
// Corner case: A full-sized block of all-zero ciphertext bytes is translated
// to an all-zero plaintext block, i.e. file hole passtrough.
func (be *ContentEnc) DecryptBlock(ciphertext []byte, blockNo uint64, fileId []byte) ([]byte, error) {

	// Empty block?
	if len(ciphertext) == 0 {
		return ciphertext, nil
	}

	// All-zero block?
	if bytes.Equal(ciphertext, be.allZeroBlock) {
		tlog.Debug.Printf("DecryptBlock: file hole encountered")
		return make([]byte, be.plainBS), nil
	}

	if len(ciphertext) < be.cryptoCore.IVLen {
		tlog.Warn.Printf("DecryptBlock: Block is too short: %d bytes", len(ciphertext))
		return nil, errors.New("Block is too short")
	}

	// Extract nonce
	nonce := ciphertext[:be.cryptoCore.IVLen]
	ciphertextOrig := ciphertext
	ciphertext = ciphertext[be.cryptoCore.IVLen:]

	// Decrypt
	var plaintext []byte
	aData := make([]byte, 8)
	aData = append(aData, fileId...)
	binary.BigEndian.PutUint64(aData, blockNo)
	plaintext, err := be.cryptoCore.Gcm.Open(plaintext, nonce, ciphertext, aData)

	if err != nil {
		tlog.Warn.Printf("DecryptBlock: %s, len=%d", err.Error(), len(ciphertextOrig))
		tlog.Debug.Println(hex.Dump(ciphertextOrig))
		return nil, err
	}

	return plaintext, nil
}

// EncryptBlocks - Encrypt a number of blocks
// Used for reverse mode
func (be *ContentEnc) EncryptBlocks(plaintext []byte, firstBlockNo uint64, fileId []byte) []byte {
	inBuf := bytes.NewBuffer(plaintext)
	var outBuf bytes.Buffer
	for blockNo := firstBlockNo; inBuf.Len() > 0; blockNo++ {
		inBlock := inBuf.Next(int(be.plainBS))
		outBlock := be.EncryptBlock(inBlock, blockNo, fileId)
		outBuf.Write(outBlock)
	}
	return outBuf.Bytes()
}

// encryptBlock - Encrypt and add IV and MAC
func (be *ContentEnc) EncryptBlock(plaintext []byte, blockNo uint64, fileID []byte) []byte {

	// Empty block?
	if len(plaintext) == 0 {
		return plaintext
	}

	// Get fresh nonce
	nonce := be.cryptoCore.GcmIVGen.Get()

	// Authenticate block with block number and file ID
	aData := make([]byte, 8)
	binary.BigEndian.PutUint64(aData, blockNo)
	aData = append(aData, fileID...)

	// Encrypt plaintext and append to nonce
	ciphertext := be.cryptoCore.Gcm.Seal(nonce, nonce, plaintext, aData)

	return ciphertext
}

// MergeBlocks - Merge newData into oldData at offset
// New block may be bigger than both newData and oldData
func (be *ContentEnc) MergeBlocks(oldData []byte, newData []byte, offset int) []byte {

	// Make block of maximum size
	out := make([]byte, be.plainBS)

	// Copy old and new data into it
	copy(out, oldData)
	l := len(newData)
	copy(out[offset:offset+l], newData)

	// Crop to length
	outLen := len(oldData)
	newLen := offset + len(newData)
	if outLen < newLen {
		outLen = newLen
	}
	return out[0:outLen]
}
