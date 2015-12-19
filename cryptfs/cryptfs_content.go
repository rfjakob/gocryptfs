package cryptfs

// File content encryption / decryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
)

// md5sum - debug helper, return md5 hex string
func md5sum(buf []byte) string {
	rawHash := md5.Sum(buf)
	hash := hex.EncodeToString(rawHash[:])
	return hash
}

type CryptFile struct {
	file *os.File
	gcm  cipher.AEAD
}

// DecryptBlocks - Decrypt a number of blocks
func (be *CryptFS) DecryptBlocks(ciphertext []byte, firstBlockNo uint64, fileId []byte) ([]byte, error) {
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
func (be *CryptFS) DecryptBlock(ciphertext []byte, blockNo uint64, fileId []byte) ([]byte, error) {

	// Empty block?
	if len(ciphertext) == 0 {
		return ciphertext, nil
	}

	// All-zero block?
	if bytes.Equal(ciphertext, be.allZeroBlock) {
		Debug.Printf("DecryptBlock: file hole encountered\n")
		return make([]byte, be.plainBS), nil
	}

	if len(ciphertext) < be.gcmIVLen {
		Warn.Printf("DecryptBlock: Block is too short: %d bytes\n", len(ciphertext))
		return nil, errors.New("Block is too short")
	}

	// Extract nonce
	nonce := ciphertext[:be.gcmIVLen]
	ciphertextOrig := ciphertext
	ciphertext = ciphertext[be.gcmIVLen:]

	// Decrypt
	var plaintext []byte
	aData := make([]byte, 8)
	aData = append(aData, fileId...)
	binary.BigEndian.PutUint64(aData, blockNo)
	plaintext, err := be.gcm.Open(plaintext, nonce, ciphertext, aData)

	if err != nil {
		Warn.Printf("DecryptBlock: %s, len=%d, md5=%s\n", err.Error(), len(ciphertextOrig), Warn.Md5sum(ciphertextOrig))
		Debug.Println(hex.Dump(ciphertextOrig))
		return nil, err
	}

	return plaintext, nil
}

// encryptBlock - Encrypt and add IV and MAC
func (be *CryptFS) EncryptBlock(plaintext []byte, blockNo uint64, fileID []byte) []byte {

	// Empty block?
	if len(plaintext) == 0 {
		return plaintext
	}

	// Get fresh nonce
	nonce := be.gcmIVGen.Get()

	// Authenticate block with block number and file ID
	aData := make([]byte, 8)
	binary.BigEndian.PutUint64(aData, blockNo)
	aData = append(aData, fileID...)

	// Encrypt plaintext and append to nonce
	ciphertext := be.gcm.Seal(nonce, nonce, plaintext, aData)

	return ciphertext
}

// MergeBlocks - Merge newData into oldData at offset
// New block may be bigger than both newData and oldData
func (be *CryptFS) MergeBlocks(oldData []byte, newData []byte, offset int) []byte {

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
