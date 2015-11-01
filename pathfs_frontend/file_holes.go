package pathfs_frontend

import (
	"github.com/hanwen/go-fuse/fuse"
	"github.com/rfjakob/gocryptfs/cryptfs"
)

// Will a write to offset "off" create a file hole?
func (f *file) createsHole(plainSize uint64, off int64) bool {
	nextBlock := f.cfs.PlainOffToBlockNo(plainSize)
	targetBlock := f.cfs.PlainOffToBlockNo(uint64(off))
	if targetBlock > nextBlock {
		return true
	}
	return false
}

// Zero-pad the file of size plainSize to the next block boundary
func (f *file) zeroPad(plainSize uint64) fuse.Status {
	lastBlockLen := plainSize % f.cfs.PlainBS()
	missing := f.cfs.PlainBS() - lastBlockLen
	pad := make([]byte, missing)
	cryptfs.Debug.Printf("zeroPad: Writing %d bytes\n", missing)
	_, status := f.doWrite(pad, int64(plainSize))
	return status
}
