package fusefrontend

// Helper functions for sparse files (files with holes)

import (
	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Will a write to offset "off" create a file hole?
func (f *file) createsHole(plainSize uint64, off int64) bool {
	nextBlock := f.contentEnc.PlainOffToBlockNo(plainSize)
	targetBlock := f.contentEnc.PlainOffToBlockNo(uint64(off))
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
