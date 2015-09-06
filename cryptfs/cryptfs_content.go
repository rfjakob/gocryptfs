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
		pBlock, err := be.DecryptBlock(cBlock)
		if err != nil {
			break
		}
		pBuf.Write(pBlock)
	}
	return pBuf.Bytes(), err
}

// DecryptBlock - Verify and decrypt GCM block
func (be *CryptFS) DecryptBlock(ciphertext []byte) ([]byte, error) {

	// Empty block?
	if len(ciphertext) == 0 {
		return ciphertext, nil
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

// Split a plaintext byte range into (possible partial) blocks
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
	if size > 0 {
		overhead := be.cipherBS - be.plainBS
		nBlocks := (size + be.cipherBS - 1) / be.cipherBS
		size -= nBlocks * overhead
	}
	return size
}

func (be *CryptFS) minu64(x uint64, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
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
