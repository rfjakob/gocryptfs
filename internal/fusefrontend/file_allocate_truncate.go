package fusefrontend

// FUSE operations Truncate and Allocate on file handles
// i.e. ftruncate and fallocate

import (
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Only warn once
var allocateWarnOnce sync.Once

// Allocate - FUSE call, fallocate(2)
// This is not implemented yet in gocryptfs, but it is neither in EncFS. This
// suggests that the user demand is low.
func (f *file) Allocate(off uint64, sz uint64, mode uint32) fuse.Status {
	allocateWarnOnce.Do(func() {
		tlog.Warn.Printf("fallocate(2) is not supported, returning ENOSYS - see https://github.com/rfjakob/gocryptfs/issues/1")
	})
	return fuse.ENOSYS
}

// Truncate - FUSE call
func (f *file) Truncate(newSize uint64) fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	if f.released {
		// The file descriptor has been closed concurrently.
		tlog.Warn.Printf("ino%d fh%d: Truncate on released file", f.ino, f.intFd())
		return fuse.EBADF
	}
	wlock.lock(f.ino)
	defer wlock.unlock(f.ino)
	var err error
	// Common case first: Truncate to zero
	if newSize == 0 {
		err = syscall.Ftruncate(int(f.fd.Fd()), 0)
		if err != nil {
			tlog.Warn.Printf("ino%d fh%d: Ftruncate(fd, 0) returned error: %v", f.ino, f.intFd(), err)
			return fuse.ToStatus(err)
		}
		// Truncate to zero kills the file header
		f.header = nil
		return fuse.OK
	}
	// We need the old file size to determine if we are growing or shrinking
	// the file
	fi, err := f.fd.Stat()
	if err != nil {
		tlog.Warn.Printf("ino%d fh%d: Truncate: Fstat failed: %v", f.ino, f.intFd(), err)
		return fuse.ToStatus(err)
	}
	oldSize := f.contentEnc.CipherSizeToPlainSize(uint64(fi.Size()))
	{
		oldB := float32(oldSize) / float32(f.contentEnc.PlainBS())
		newB := float32(newSize) / float32(f.contentEnc.PlainBS())
		tlog.Debug.Printf("ino%d: FUSE Truncate from %.2f to %.2f blocks (%d to %d bytes)", f.ino, oldB, newB, oldSize, newSize)
	}
	// File size stays the same - nothing to do
	if newSize == oldSize {
		return fuse.OK
	}
	// File grows
	if newSize > oldSize {
		// File was empty, create new header
		if oldSize == 0 {
			err = f.createHeader()
			if err != nil {
				return fuse.ToStatus(err)
			}
		}
		// New blocks to add
		addBlocks := f.contentEnc.ExplodePlainRange(oldSize, newSize-oldSize)
		if len(addBlocks) >= 2 {
			f.zeroPad(oldSize)
		}
		lastBlock := addBlocks[len(addBlocks)-1]
		if lastBlock.IsPartial() {
			off := lastBlock.BlockPlainOff()
			_, status := f.doWrite(make([]byte, lastBlock.Length), int64(off+lastBlock.Skip))
			return status
		} else {
			off := lastBlock.BlockCipherOff()
			err = syscall.Ftruncate(f.intFd(), int64(off+f.contentEnc.CipherBS()))
			if err != nil {
				tlog.Warn.Printf("Truncate: grow Ftruncate returned error: %v", err)
			}
			return fuse.ToStatus(err)
		}
	} else {
		// File shrinks
		blockNo := f.contentEnc.PlainOffToBlockNo(newSize)
		cipherOff := f.contentEnc.BlockNoToCipherOff(blockNo)
		plainOff := f.contentEnc.BlockNoToPlainOff(blockNo)
		lastBlockLen := newSize - plainOff
		var data []byte
		if lastBlockLen > 0 {
			var status fuse.Status
			data, status = f.doRead(plainOff, lastBlockLen)
			if status != fuse.OK {
				tlog.Warn.Printf("Truncate: shrink doRead returned error: %v", err)
				return status
			}
		}
		// Truncate down to the last complete block
		err = syscall.Ftruncate(int(f.fd.Fd()), int64(cipherOff))
		if err != nil {
			tlog.Warn.Printf("Truncate: shrink Ftruncate returned error: %v", err)
			return fuse.ToStatus(err)
		}
		// Append partial block
		if lastBlockLen > 0 {
			_, status := f.doWrite(data, int64(plainOff))
			return status
		}
		return fuse.OK
	}
}
