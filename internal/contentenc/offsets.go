package contentenc

import (
	"log"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Contentenc methods that translate offsets between ciphertext and plaintext

// PlainOffToBlockNo converts a plaintext offset to the ciphertext block number.
func (be *ContentEnc) PlainOffToBlockNo(plainOffset uint64) uint64 {
	return plainOffset / be.plainBS
}

// CipherOffToBlockNo converts the ciphertext offset to the plaintext block number.
func (be *ContentEnc) CipherOffToBlockNo(cipherOffset uint64) uint64 {
	if cipherOffset < HeaderLen {
		log.Panicf("BUG: offset %d is inside the file header", cipherOffset)
	}
	return (cipherOffset - HeaderLen) / be.cipherBS
}

// BlockNoToCipherOff gets the ciphertext offset of block "blockNo"
func (be *ContentEnc) BlockNoToCipherOff(blockNo uint64) uint64 {
	return HeaderLen + blockNo*be.cipherBS
}

// BlockNoToPlainOff gets the plaintext offset of block "blockNo"
func (be *ContentEnc) BlockNoToPlainOff(blockNo uint64) uint64 {
	return blockNo * be.plainBS
}

// CipherSizeToPlainSize calculates the plaintext size from a ciphertext size
func (be *ContentEnc) CipherSizeToPlainSize(cipherSize uint64) uint64 {
	// Zero-sized files stay zero-sized
	if cipherSize == 0 {
		return 0
	}

	if cipherSize == HeaderLen {
		tlog.Warn.Printf("cipherSize %d == header size: interrupted write?\n", cipherSize)
		return 0
	}

	if cipherSize < HeaderLen {
		tlog.Warn.Printf("cipherSize %d < header size %d: corrupt file\n", cipherSize, HeaderLen)
		return 0
	}

	// Block number at last byte
	blockNo := be.CipherOffToBlockNo(cipherSize - 1)
	blockCount := blockNo + 1

	overhead := be.BlockOverhead()*blockCount + HeaderLen

	return cipherSize - overhead
}

// PlainSizeToCipherSize calculates the ciphertext size from a plaintext size
func (be *ContentEnc) PlainSizeToCipherSize(plainSize uint64) uint64 {
	// Zero-sized files stay zero-sized
	if plainSize == 0 {
		return 0
	}

	// Block number at last byte
	blockNo := be.PlainOffToBlockNo(plainSize - 1)
	blockCount := blockNo + 1

	overhead := be.BlockOverhead()*blockCount + HeaderLen

	return plainSize + overhead
}

// ExplodePlainRange splits a plaintext byte range into (possibly partial) blocks
// Returns an empty slice if length == 0.
func (be *ContentEnc) ExplodePlainRange(offset uint64, length uint64) []IntraBlock {
	var blocks []IntraBlock
	var nextBlock IntraBlock
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

// ExplodeCipherRange splits a ciphertext byte range into (possibly partial)
// blocks This is used in reverse mode when reading files
func (be *ContentEnc) ExplodeCipherRange(offset uint64, length uint64) []IntraBlock {
	var blocks []IntraBlock
	var nextBlock IntraBlock
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

// BlockOverhead returns the per-block overhead.
func (be *ContentEnc) BlockOverhead() uint64 {
	return be.cipherBS - be.plainBS
}

// MinUint64 returns the minimum of two uint64 values.
func MinUint64(x uint64, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}
