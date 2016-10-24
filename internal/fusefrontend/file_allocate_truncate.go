package fusefrontend

// FUSE operations Truncate and Allocate on file handles
// i.e. ftruncate and fallocate

import (
	"log"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// FALLOC_DEFAULT is a "normal" fallocate operation
const FALLOC_DEFAULT = 0x00

// FALLOC_FL_KEEP_SIZE allocates disk space while not modifying the file size
const FALLOC_FL_KEEP_SIZE = 0x01

// Only warn once
var allocateWarnOnce sync.Once

// Allocate - FUSE call for fallocate(2)
//
// mode=FALLOC_FL_KEEP_SIZE is implemented directly.
//
// mode=FALLOC_DEFAULT is implemented as a two-step process:
//
//   (1) Allocate the space using FALLOC_FL_KEEP_SIZE
//   (2) Set the file size using ftruncate (via truncateGrowFile)
//
// This allows us to reuse the file grow mechanics from Truncate as they are
// complicated and hard to get right.
//
// Other modes (hole punching, zeroing) are not supported.
func (f *file) Allocate(off uint64, sz uint64, mode uint32) fuse.Status {
	if mode != FALLOC_DEFAULT && mode != FALLOC_FL_KEEP_SIZE {
		f := func() {
			tlog.Warn.Print("fallocate: only mode 0 (default) and 1 (keep size) are supported")
		}
		allocateWarnOnce.Do(f)
		return fuse.Status(syscall.EOPNOTSUPP)
	}

	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	if f.released {
		return fuse.EBADF
	}
	wlock.lock(f.ino)
	defer wlock.unlock(f.ino)

	blocks := f.contentEnc.ExplodePlainRange(off, sz)
	firstBlock := blocks[0]
	lastBlock := blocks[len(blocks)-1]

	// Step (1): Allocate the space the user wants using FALLOC_FL_KEEP_SIZE.
	// This will fill file holes and/or allocate additional space past the end of
	// the file.
	cipherOff := firstBlock.BlockCipherOff()
	cipherSz := lastBlock.BlockCipherOff() - cipherOff +
		f.contentEnc.PlainSizeToCipherSize(lastBlock.Skip+lastBlock.Length)
	err := syscallcompat.Fallocate(f.intFd(), FALLOC_FL_KEEP_SIZE, int64(cipherOff), int64(cipherSz))
	tlog.Debug.Printf("Allocate off=%d sz=%d mode=%x cipherOff=%d cipherSz=%d\n",
		off, sz, mode, cipherOff, cipherSz)
	if err != nil {
		return fuse.ToStatus(err)
	}
	if mode == FALLOC_FL_KEEP_SIZE {
		// The user did not want to change the apparent size. We are done.
		return fuse.OK
	}
	// Step (2): Grow the apparent file size
	// We need the old file size to determine if we are growing the file at all.
	newPlainSz := off + sz
	oldPlainSz, err := f.statPlainSize()
	if err != nil {
		return fuse.ToStatus(err)
	}
	if newPlainSz <= oldPlainSz {
		// The new size is smaller (or equal). Fallocate with mode = 0 never
		// truncates a file, so we are done.
		return fuse.OK
	}
	// The file grows. The space has already been allocated in (1), so what is
	// left to do is to pad the first and last block and call truncate.
	// truncateGrowFile does just that.
	return f.truncateGrowFile(oldPlainSz, newPlainSz)
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
	oldSize, err := f.statPlainSize()
	if err != nil {
		return fuse.ToStatus(err)
	}

	oldB := float32(oldSize) / float32(f.contentEnc.PlainBS())
	newB := float32(newSize) / float32(f.contentEnc.PlainBS())
	tlog.Debug.Printf("ino%d: FUSE Truncate from %.2f to %.2f blocks (%d to %d bytes)", f.ino, oldB, newB, oldSize, newSize)

	// File size stays the same - nothing to do
	if newSize == oldSize {
		return fuse.OK
	}
	// File grows
	if newSize > oldSize {
		return f.truncateGrowFile(oldSize, newSize)
	}

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

// statPlainSize stats the file and returns the plaintext size
func (f *file) statPlainSize() (uint64, error) {
	fi, err := f.fd.Stat()
	if err != nil {
		tlog.Warn.Printf("ino%d fh%d: statPlainSize: %v", f.ino, f.intFd(), err)
		return 0, err
	}
	cipherSz := uint64(fi.Size())
	plainSz := uint64(f.contentEnc.CipherSizeToPlainSize(cipherSz))
	return plainSz, nil
}

// truncateGrowFile extends a file using seeking or ftruncate performing RMW on
// the first and last block as necessary. New blocks in the middle become
// file holes unless they have been fallocate()'d beforehand.
func (f *file) truncateGrowFile(oldPlainSz uint64, newPlainSz uint64) fuse.Status {
	if newPlainSz <= oldPlainSz {
		log.Panicf("BUG: newSize=%d <= oldSize=%d", newPlainSz, oldPlainSz)
	}
	var err error
	// File was empty, create new header
	if oldPlainSz == 0 {
		err = f.createHeader()
		if err != nil {
			return fuse.ToStatus(err)
		}
	}
	// New blocks to add
	addBlocks := f.contentEnc.ExplodePlainRange(oldPlainSz, newPlainSz-oldPlainSz)
	if oldPlainSz > 0 && len(addBlocks) >= 2 {
		// Zero-pad the first block (unless the first block is also the last block)
		f.zeroPad(oldPlainSz)
	}
	lastBlock := addBlocks[len(addBlocks)-1]
	if lastBlock.IsPartial() {
		// Write at the new end of the file. The seek implicitly grows the file
		// (creates a file hole) and doWrite() takes care of RMW.
		off := lastBlock.BlockPlainOff()
		_, status := f.doWrite(make([]byte, lastBlock.Length), int64(off+lastBlock.Skip))
		return status
	}

	off := lastBlock.BlockCipherOff()
	err = syscall.Ftruncate(f.intFd(), int64(off+f.contentEnc.CipherBS()))
	if err != nil {
		tlog.Warn.Printf("Truncate: grow Ftruncate returned error: %v", err)
	}
	return fuse.ToStatus(err)
}
