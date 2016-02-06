package contentenc

// File content encryption / decryption

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/rfjakob/gocryptfs/internal/toggledlog"
)

// DecryptBlocks - Decrypt a number of blocks
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
		toggledlog.Debug.Printf("DecryptBlock: file hole encountered")
		return make([]byte, be.plainBS), nil
	}

	if len(ciphertext) < be.cryptoCore.IVLen {
		toggledlog.Warn.Printf("DecryptBlock: Block is too short: %d bytes", len(ciphertext))
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
		toggledlog.Warn.Printf("DecryptBlock: %s, len=%d", err.Error(), len(ciphertextOrig))
		toggledlog.Debug.Println(hex.Dump(ciphertextOrig))
		return nil, err
	}

	return plaintext, nil
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
