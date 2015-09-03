package gocryptfs

import (
	"fmt"
	"os"
	"io"
	"errors"
)

// readCipherBlock - Read ciphertext block number "blockNo", decrypt,
// return plaintext
func (be *Backend) readCipherBlock(blockNo int64, f *os.File) ([]byte, error) {
	off := blockNo * int64(be.cipherBS)
	buf := make([]byte, be.cipherBS)

	readN, err := f.ReadAt(buf, off)

	if err != nil && err != io.EOF {
		return nil, err
	}

	// Truncate buffer to actually read bytes
	buf = buf[:readN]

	// Empty block?file:///home/jakob/go/src/github.com/rfjakob/gocryptfs-bazil/backend/backend.go

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
	blockNo int64  // Block number in file
	offset  int64  // Offset into block plaintext
	length  int64  // Length of data from this block
}

// Split a plaintext byte range into (possible partial) blocks
func (be *Backend) splitRange(offset int64, length int64, f *os.File) []intraBlock {
	var b intraBlock
	var parts []intraBlock

	for length > 0 {
		b.blockNo = offset / be.plainBS
		b.offset = offset % be.plainBS
		b.length = be.min64(length, be.plainBS - b.offset)
		parts = append(parts, b)
		offset += b.length
		length -= b.length
	}
	return parts
}

func (be *Backend) min64(x int64, y int64) int64 {
	if x < y {
		return x
	}
	return y
}

// writeCipherBlock - Encrypt plaintext and write it to file block "blockNo"
func (be *Backend) writeCipherBlock(blockNo int64, plain []byte, f *os.File) error {

	if int64(len(plain)) > be.plainBS {
		panic("writeCipherBlock: Cannot write block that is larger than plainBS")
	}

	// Get fresh nonce
	nonce := gcmNonce.Get()
	// Encrypt data and append to nonce
	cipherBuf := be.gcm.Seal(nonce, nonce, plain, nil)

	// WriteAt retries short writes autmatically
	written, err := f.WriteAt(cipherBuf, blockNo * be.cipherBS)

	debug.Printf("writeCipherBlock: wrote %d ciphertext bytes to block %d\n",
		written, blockNo)

	return err
}

// Perform RMW cycle on block
// Write "data" into file location specified in "b"
func (be *Backend) rmwWrite(b intraBlock, data []byte, f *os.File) error {
	if b.length != int64(len(data)) {
		panic("Length mismatch")
	}

	oldBlock, err := be.readCipherBlock(b.blockNo, f)
	if err != nil {
		return err
	}
	newBlockLen := b.offset + b.length
	debug.Printf("newBlockLen := %d + %d\n", b.offset, b.length)
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
	copy(newBlock[b.offset:b.offset + b.length], data)

	// Actual write
	err = be.writeCipherBlock(b.blockNo, newBlock, f)

	if err != nil {
		// An incomplete write to a ciphertext block means that the whole block
		// is destroyed.
		fmt.Printf("rmwWrite: Write error: %s\n", err)
	}

	return err
}
