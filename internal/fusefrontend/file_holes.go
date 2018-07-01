package fusefrontend

// Helper functions for sparse files (files with holes)

import (
	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Will a write to plaintext offset "targetOff" create a file hole in the
// ciphertext? If yes, zero-pad the last ciphertext block.
func (f *File) writePadHole(targetOff int64) fuse.Status {
	// Get the current file size.
	fi, err := f.fd.Stat()
	if err != nil {
		tlog.Warn.Printf("checkAndPadHole: Fstat failed: %v", err)
		return fuse.ToStatus(err)
	}
	plainSize := f.contentEnc.CipherSizeToPlainSize(uint64(fi.Size()))
	// Appending a single byte to the file (equivalent to writing to
	// offset=plainSize) would write to "nextBlock".
	nextBlock := f.contentEnc.PlainOffToBlockNo(plainSize)
	// targetBlock is the block the user wants to write to.
	targetBlock := f.contentEnc.PlainOffToBlockNo(uint64(targetOff))
	// The write goes into an existing block or (if the last block was full)
	// starts a new one directly after the last block. Nothing to do.
	if targetBlock <= nextBlock {
		return fuse.OK
	}
	// The write goes past the next block. nextBlock has
	// to be zero-padded to the block boundary and (at least) nextBlock+1
	// will contain a file hole in the ciphertext.
	status := f.zeroPad(plainSize)
	if status != fuse.OK {
		tlog.Warn.Printf("zeroPad returned error %v", status)
		return status
	}
	return fuse.OK
}

// Zero-pad the file of size plainSize to the next block boundary. This is a no-op
// if the file is already block-aligned.
func (f *File) zeroPad(plainSize uint64) fuse.Status {
	lastBlockLen := plainSize % f.contentEnc.PlainBS()
	if lastBlockLen == 0 {
		// Already block-aligned
		return fuse.OK
	}
	missing := f.contentEnc.PlainBS() - lastBlockLen
	pad := make([]byte, missing)
	tlog.Debug.Printf("zeroPad: Writing %d bytes\n", missing)
	_, status := f.doWrite(pad, int64(plainSize))
	return status
}
