package cryptfs

import (
	"fmt"
	"os"
	"io"
	"errors"
	"crypto/cipher"
)

type CryptFile struct {
	file *os.File
	gcm cipher.AEAD
	plainBS	int64
	cipherBS int64
}

// decryptBlock - Verify and decrypt GCM block
func (be *CryptFS) DecryptBlock(ciphertext []byte) ([]byte, error) {

	// Empty block?
	if len(ciphertext) == 0 {
		return ciphertext, nil
	}

	if len(ciphertext) < NONCE_LEN {
		warn.Printf("decryptBlock: Block is too short: %d bytes\n", len(ciphertext))
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

// readCipherBlock - Read ciphertext block number "blockNo", decrypt,
// return plaintext
func (be *CryptFile) readCipherBlock(blockNo int64) ([]byte, error) {
	off := blockNo * int64(be.cipherBS)
	buf := make([]byte, be.cipherBS)

	readN, err := be.file.ReadAt(buf, off)

	if err != nil && err != io.EOF {
		return nil, err
	}

	// Truncate buffer to actually read bytes
	buf = buf[:readN]

	// Empty block?
	if len(buf) == 0 {
		return buf, nil
	}

	if len(buf) < NONCE_LEN {
		warn.Printf("readCipherBlock: Block is too short: %d bytes\n", len(buf))
		return nil, errors.New("Block is too short")
	}

	// Extract nonce
	nonce := buf[:NONCE_LEN]
	buf = buf[NONCE_LEN:]

	// Decrypt
	var plainBuf []byte
	plainBuf, err = be.gcm.Open(plainBuf, nonce, buf, nil)
	if err != nil {
		fmt.Printf("gcm.Open() failed: %d\n", err)
		return nil, err
	}

	return plainBuf, nil
}

// intraBlock identifies a part of a file block
type intraBlock struct {
	BlockNo int64  // Block number in file
	Offset  int64  // Offset into block plaintext
	Length  int64  // Length of data from this block
	fs    *CryptFS
}

// isPartial - is the block partial? This means we have to do read-modify-write.
func (ib *intraBlock) IsPartial() bool {
	if ib.Offset > 0 || ib.Length < ib.fs.plainBS {
		return true
	}
	return false
}

// ciphertextRange - get byte range in ciphertext file corresponding to BlockNo
func (ib *intraBlock) CiphertextRange() (offset int64, length int64) {
	return ib.BlockNo * ib.fs.cipherBS, ib.fs.cipherBS
}

// CropBlock - crop a full plaintext block down to the relevant part
func (ib *intraBlock) CropBlock(d []byte) []byte{
	return d[ib.Offset:ib.Offset+ib.Length]
}

// Split a plaintext byte range into (possible partial) blocks
func (be *CryptFS) SplitRange(offset int64, length int64) []intraBlock {
	var b intraBlock
	var parts []intraBlock

	b.fs = be

	for length > 0 {
		b.BlockNo = offset / be.plainBS
		b.Offset = offset % be.plainBS
		b.Length = be.min64(length, be.plainBS - b.Offset)
		parts = append(parts, b)
		offset += b.Length
		length -= b.Length
	}
	return parts
}

func (be *CryptFS) min64(x int64, y int64) int64 {
	if x < y {
		return x
	}
	return y
}

// writeCipherBlock - Encrypt plaintext and write it to file block "blockNo"
func (be *CryptFile) writeCipherBlock(blockNo int64, plain []byte) error {

	if int64(len(plain)) > be.plainBS {
		panic("writeCipherBlock: Cannot write block that is larger than plainBS")
	}

	// Get fresh nonce
	nonce := gcmNonce.Get()
	// Encrypt data and append to nonce
	cipherBuf := be.gcm.Seal(nonce, nonce, plain, nil)

	// WriteAt retries short writes autmatically
	written, err := be.file.WriteAt(cipherBuf, blockNo * be.cipherBS)

	debug.Printf("writeCipherBlock: wrote %d ciphertext bytes to block %d\n",
		written, blockNo)

	return err
}

// Perform RMW cycle on block
// Write "data" into file location specified in "b"
func (be *CryptFile) rmwWrite(b intraBlock, data []byte, f *os.File) error {
	if b.Length != int64(len(data)) {
		panic("Length mismatch")
	}

	oldBlock, err := be.readCipherBlock(b.BlockNo)
	if err != nil {
		return err
	}
	newBlockLen := b.Offset + b.Length
	debug.Printf("newBlockLen := %d + %d\n", b.Offset, b.Length)
	var newBlock []byte

	// Write goes beyond the old block and grows the file?
	// Must create a bigger newBlock
	if newBlockLen > int64(len(oldBlock)) {
		newBlock = make([]byte, newBlockLen)
	} else {
		newBlock = make([]byte, len(oldBlock))
	}

	// Fill with old data
	copy(newBlock, oldBlock)
	// Then overwrite the relevant parts with new data
	copy(newBlock[b.Offset:b.Offset + b.Length], data)

	// Actual write
	err = be.writeCipherBlock(b.BlockNo, newBlock)

	if err != nil {
		// An incomplete write to a ciphertext block means that the whole block
		// is destroyed.
		fmt.Printf("rmwWrite: Write error: %s\n", err)
	}

	return err
}
