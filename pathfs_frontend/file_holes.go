package pathfs_frontend

import (
	"fmt"
	"github.com/hanwen/go-fuse/fuse"
	"github.com/rfjakob/gocryptfs/cryptfs"
)

// Will a write to offset "off" create a file hole?
func (f *file) createsHole(cipherSize uint64, off int64) bool {
	nextBlock := f.cfs.BlockNoCipherOff(cipherSize)
	targetBlock := f.cfs.BlockNoPlainOff(uint64(off))
	if targetBlock > nextBlock {
		return true
	}
	return false
}

// Zero-pad the file if a write to "off" creates a file hole
func (f *file) conditionalZeroPad(off int64) fuse.Status {
	fi, err := f.fd.Stat()
	if err != nil {
		cryptfs.Warn.Printf("conditionalZeroPad: Stat: %v\n", err)
		return fuse.ToStatus(err)
	}
	cipherSize := uint64(fi.Size())

	if f.createsHole(cipherSize, off) == false {
		return fuse.OK
	}

	plainSize := f.cfs.PlainSize(cipherSize)
	lastBlockLen := plainSize % f.cfs.PlainBS()
	missing := f.cfs.PlainBS() - lastBlockLen
	pad := make([]byte, missing)
	_, status := f.doWrite(pad, int64(plainSize))
	return status
}
