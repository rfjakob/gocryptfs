package fusefrontend

// Helper functions for sparse files (files with holes)

import (
	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Will a write to plaintext offset "off" create a file hole in the ciphertext?
func (f *file) createsCiphertextHole(plainSize uint64, off int64) bool {
	// Appending a single byte to the file (equivalent to writing to
	// offset=plainSize) would write to "nextBlock".
	nextBlock := f.contentEnc.PlainOffToBlockNo(plainSize)
	// targetBlock is the block the user wants to write to.
	targetBlock := f.contentEnc.PlainOffToBlockNo(uint64(off))
	// If the write goes past the next block, nextBlock will have
	// to be zero-padded to the block boundary and at least nextBlock+1
	// becomes a file hole in the ciphertext.
	return targetBlock > nextBlock
}

// Zero-pad the file of size plainSize to the next block boundary
func (f *file) zeroPad(plainSize uint64) fuse.Status {
	lastBlockLen := plainSize % f.contentEnc.PlainBS()
	missing := f.contentEnc.PlainBS() - lastBlockLen
	if missing == 0 {
		// Already block-aligned
		return fuse.OK
	}
	pad := make([]byte, missing)
	tlog.Debug.Printf("zeroPad: Writing %d bytes\n", missing)
	_, status := f.doWrite(pad, int64(plainSize))
	return status
}
