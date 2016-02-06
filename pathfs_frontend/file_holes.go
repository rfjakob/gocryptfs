package pathfs_frontend

// Helper functions for sparse files (files with holes)

import (
	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/toggledlog"
)

// Will a write to offset "off" create a file hole?
func (f *file) createsHole(plainSize uint64, off int64) bool {
	nextBlock := f.contentEnc.PlainOffToBlockNo(plainSize)
	targetBlock := f.contentEnc.PlainOffToBlockNo(uint64(off))
	if targetBlock > nextBlock {
		return true
	}
	return false
}

// Zero-pad the file of size plainSize to the next block boundary
func (f *file) zeroPad(plainSize uint64) fuse.Status {
	lastBlockLen := plainSize % f.contentEnc.PlainBS()
	missing := f.contentEnc.PlainBS() - lastBlockLen
	pad := make([]byte, missing)
	toggledlog.Debug.Printf("zeroPad: Writing %d bytes\n", missing)
	_, status := f.doWrite(pad, int64(plainSize))
	return status
}
