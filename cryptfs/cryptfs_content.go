package cryptfs

// File content encryption / decryption

import (
	"bytes"
	"os"
	"errors"
	"crypto/cipher"
)

type CryptFile struct {
	file *os.File
	gcm cipher.AEAD
}

// DecryptBlocks - Decrypt a number of blocks
func (be *CryptFS) DecryptBlocks(ciphertext []byte) ([]byte, error) {
	cBuf := bytes.NewBuffer(ciphertext)
	var err error
	var pBuf bytes.Buffer
	for cBuf.Len() > 0 {
		cBlock := cBuf.Next(int(be.cipherBS))
		var pBlock []byte
		pBlock, err = be.DecryptBlock(cBlock)
		if err != nil {
			break
		}
		pBuf.Write(pBlock)
	}
	return pBuf.Bytes(), err
}

// DecryptBlock - Verify and decrypt GCM block
//
// Corner case: A full-sized block of all-zero ciphertext bytes is translated
// to an all-zero plaintext block, i.e. file hole passtrough.
func (be *CryptFS) DecryptBlock(ciphertext []byte) ([]byte, error) {

	// Empty block?
	if len(ciphertext) == 0 {
		return ciphertext, nil
	}

	// All-zero block?
	if bytes.Equal(ciphertext, be.allZeroBlock) {
		Debug.Printf("DecryptBlock: file hole encountered\n")
		return make([]byte, be.plainBS), nil
	}

	if len(ciphertext) < NONCE_LEN {
		Warn.Printf("decryptBlock: Block is too short: %d bytes\n", len(ciphertext))
		return nil, errors.New("Block is too short")
	}

	// Extract nonce
	nonce := ciphertext[:NONCE_LEN]
	ciphertext = ciphertext[NONCE_LEN:]

	// Decrypt
	var plaintext []byte

	plaintext, err := be.gcm.Open(plaintext, nonce, ciphertext, nil)

	if err != nil {
		Warn.Printf("DecryptBlock: %s\n", err.Error())
		return nil, err
	}

	return plaintext, nil
}

// encryptBlock - Encrypt and add MAC using GCM
func (be *CryptFS) EncryptBlock(plaintext []byte) []byte {

	// Empty block?
	if len(plaintext) == 0 {
		return plaintext
	}

	// Get fresh nonce
	nonce := gcmNonce.Get()

	// Encrypt plaintext and append to nonce
	ciphertext := be.gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext
}

// Split a plaintext byte range into (possibly partial) blocks
func (be *CryptFS) SplitRange(offset uint64, length uint64) []intraBlock {
	var b intraBlock
	var parts []intraBlock

	b.fs = be

	for length > 0 {
		b.BlockNo = offset / be.plainBS
		b.Offset = offset % be.plainBS
		b.Length = be.minu64(length, be.plainBS - b.Offset)
		parts = append(parts, b)
		offset += b.Length
		length -= b.Length
	}
	return parts
}

// PlainSize - calculate plaintext size from ciphertext size
func (be *CryptFS) PlainSize(size uint64) uint64 {

	// Zero sized files stay zero-sized
	if size == 0 {
		return 0
	}

	overhead := be.cipherBS - be.plainBS
	nBlocks := (size + be.cipherBS - 1) / be.cipherBS
	if nBlocks * overhead > size {
		Warn.Printf("PlainSize: Negative size, returning 0 instead\n")
		return 0
	}
	size -= nBlocks * overhead

	return size
}

// CipherSize - calculate ciphertext size from plaintext size
func (be *CryptFS) CipherSize(size uint64) uint64 {
	overhead := be.cipherBS - be.plainBS
	nBlocks := (size + be.plainBS - 1) / be.plainBS
	size += nBlocks * overhead

	return size
}

func (be *CryptFS) minu64(x uint64, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}

// CiphertextRange - Get byte range in backing ciphertext corresponding
// to plaintext range. Returns a range aligned to ciphertext blocks.
func (be *CryptFS) CiphertextRange(offset uint64, length uint64) (alignedOffset uint64, alignedLength uint64, skipBytes int) {
	// Decrypting the ciphertext will yield too many plaintext bytes. Skip this number
	// of bytes from the front.
	skip := offset % be.plainBS

	firstBlockNo := offset / be.plainBS
	lastBlockNo := ( offset + length - 1 ) / be.plainBS

	alignedOffset = firstBlockNo * be.cipherBS
	alignedLength = (lastBlockNo - firstBlockNo + 1) * be.cipherBS

	skipBytes = int(skip)
	return alignedOffset, alignedLength, skipBytes
}

// Get the byte range in the ciphertext corresponding to blocks
// (full blocks!)
func (be *CryptFS) JoinCiphertextRange(blocks []intraBlock) (uint64, uint64) {

	offset, _ := blocks[0].CiphertextRange()
	last := blocks[len(blocks)-1]
	length := (last.BlockNo - blocks[0].BlockNo + 1) * be.cipherBS

	return offset, length
}

// Crop plaintext that correspons to complete cipher blocks down to what is
// requested according to "iblocks"
func (be *CryptFS) CropPlaintext(plaintext []byte, blocks []intraBlock) []byte {
	offset := blocks[0].Offset
	last := blocks[len(blocks)-1]
	length := (last.BlockNo - blocks[0].BlockNo + 1) * be.plainBS
	var cropped []byte
	if offset + length > uint64(len(plaintext)) {
		cropped = plaintext[offset:len(plaintext)]
	} else {
		cropped = plaintext[offset:offset+length]
	}
	return cropped
}

// MergeBlocks - Merge newData into oldData at offset
// New block may be bigger than both newData and oldData
func (be *CryptFS) MergeBlocks(oldData []byte, newData []byte, offset int) []byte {

	// Make block of maximum size
	out := make([]byte, be.plainBS)

	// Copy old and new data into it
	copy(out, oldData)
	l := len(newData)
	copy(out[offset:offset + l], newData)

	// Crop to length
	outLen := len(oldData)
	newLen := offset + len(newData)
	if outLen < newLen {
		outLen = newLen
	}
	return out[0:outLen]
}
