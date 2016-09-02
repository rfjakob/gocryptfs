package contentenc

import (
	"log"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Contentenc methods that translate offsets between ciphertext and plaintext

// get the block number at plain-text offset
func (be *ContentEnc) PlainOffToBlockNo(plainOffset uint64) uint64 {
	return plainOffset / be.plainBS
}

// get the block number at cipher-text offset
func (be *ContentEnc) CipherOffToBlockNo(cipherOffset uint64) uint64 {
	if cipherOffset < HEADER_LEN {
		log.Panicf("BUG: offset %d is inside the file header", cipherOffset)
	}
	return (cipherOffset - HEADER_LEN) / be.cipherBS
}

// get ciphertext offset of block "blockNo"
func (be *ContentEnc) BlockNoToCipherOff(blockNo uint64) uint64 {
	return HEADER_LEN + blockNo*be.cipherBS
}

// get plaintext offset of block "blockNo"
func (be *ContentEnc) BlockNoToPlainOff(blockNo uint64) uint64 {
	return blockNo * be.plainBS
}

// PlainSize - calculate plaintext size from ciphertext size
func (be *ContentEnc) CipherSizeToPlainSize(cipherSize uint64) uint64 {
	// Zero-sized files stay zero-sized
	if cipherSize == 0 {
		return 0
	}

	if cipherSize == HEADER_LEN {
		tlog.Warn.Printf("cipherSize %d == header size: interrupted write?\n", cipherSize)
		return 0
	}

	if cipherSize < HEADER_LEN {
		tlog.Warn.Printf("cipherSize %d < header size %d: corrupt file\n", cipherSize, HEADER_LEN)
		return 0
	}

	// Block number at last byte
	blockNo := be.CipherOffToBlockNo(cipherSize - 1)
	blockCount := blockNo + 1

	overhead := be.BlockOverhead()*blockCount + HEADER_LEN

	return cipherSize - overhead
}

// CipherSize - calculate ciphertext size from plaintext size
func (be *ContentEnc) PlainSizeToCipherSize(plainSize uint64) uint64 {
	// Zero-sized files stay zero-sized
	if plainSize == 0 {
		return 0
	}

	// Block number at last byte
	blockNo := be.PlainOffToBlockNo(plainSize - 1)
	blockCount := blockNo + 1

	overhead := be.BlockOverhead()*blockCount + HEADER_LEN

	return plainSize + overhead
}

// Split a plaintext byte range into (possibly partial) blocks
// Returns an empty slice if length == 0.
func (be *ContentEnc) ExplodePlainRange(offset uint64, length uint64) []intraBlock {
	var blocks []intraBlock
	var nextBlock intraBlock
	nextBlock.fs = be

	for length > 0 {
		nextBlock.BlockNo = be.PlainOffToBlockNo(offset)
		nextBlock.Skip = offset - be.BlockNoToPlainOff(nextBlock.BlockNo)

		// Minimum of remaining plaintext data and remaining space in the block
		nextBlock.Length = MinUint64(length, be.plainBS-nextBlock.Skip)

		blocks = append(blocks, nextBlock)
		offset += nextBlock.Length
		length -= nextBlock.Length
	}
	return blocks
}

// Split a ciphertext byte range into (possibly partial) blocks
// This is used in reverse mode when reading files
func (be *ContentEnc) ExplodeCipherRange(offset uint64, length uint64) []intraBlock {
	var blocks []intraBlock
	var nextBlock intraBlock
	nextBlock.fs = be

	for length > 0 {
		nextBlock.BlockNo = be.CipherOffToBlockNo(offset)
		nextBlock.Skip = offset - be.BlockNoToCipherOff(nextBlock.BlockNo)

		// This block can carry up to "maxLen" payload bytes
		maxLen := be.cipherBS - nextBlock.Skip
		nextBlock.Length = maxLen
		// But if the user requested less, we truncate the block to "length".
		if length < maxLen {
			nextBlock.Length = length
		}

		blocks = append(blocks, nextBlock)
		offset += nextBlock.Length
		length -= nextBlock.Length
	}
	return blocks
}

func (be *ContentEnc) BlockOverhead() uint64 {
	return be.cipherBS - be.plainBS
}

func MinUint64(x uint64, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}
