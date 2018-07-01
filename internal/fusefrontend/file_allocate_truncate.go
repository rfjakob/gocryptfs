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
func (f *File) Allocate(off uint64, sz uint64, mode uint32) fuse.Status {
	if mode != FALLOC_DEFAULT && mode != FALLOC_FL_KEEP_SIZE {
		f := func() {
			tlog.Warn.Printf("fallocate: only mode 0 (default) and 1 (keep size) are supported")
		}
		allocateWarnOnce.Do(f)
		return fuse.Status(syscall.EOPNOTSUPP)
	}

	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	if f.released {
		return fuse.EBADF
	}
	f.fileTableEntry.ContentLock.Lock()
	defer f.fileTableEntry.ContentLock.Unlock()

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
func (f *File) Truncate(newSize uint64) fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	if f.released {
		// The file descriptor has been closed concurrently.
		tlog.Warn.Printf("ino%d fh%d: Truncate on released file", f.qIno.Ino, f.intFd())
		return fuse.EBADF
	}
	f.fileTableEntry.ContentLock.Lock()
	defer f.fileTableEntry.ContentLock.Unlock()
	var err error
	// Common case first: Truncate to zero
	if newSize == 0 {
		err = syscall.Ftruncate(int(f.fd.Fd()), 0)
		if err != nil {
			tlog.Warn.Printf("ino%d fh%d: Ftruncate(fd, 0) returned error: %v", f.qIno.Ino, f.intFd(), err)
			return fuse.ToStatus(err)
		}
		// Truncate to zero kills the file header
		f.fileTableEntry.HeaderLock.Lock()
		f.fileTableEntry.ID = nil
		f.fileTableEntry.HeaderLock.Unlock()
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
	tlog.Debug.Printf("ino%d: FUSE Truncate from %.2f to %.2f blocks (%d to %d bytes)", f.qIno.Ino, oldB, newB, oldSize, newSize)

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
		data, status = f.doRead(nil, plainOff, lastBlockLen)
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
func (f *File) statPlainSize() (uint64, error) {
	fi, err := f.fd.Stat()
	if err != nil {
		tlog.Warn.Printf("ino%d fh%d: statPlainSize: %v", f.qIno.Ino, f.intFd(), err)
		return 0, err
	}
	cipherSz := uint64(fi.Size())
	plainSz := uint64(f.contentEnc.CipherSizeToPlainSize(cipherSz))
	return plainSz, nil
}

// truncateGrowFile extends a file using seeking or ftruncate performing RMW on
// the first and last block as necessary. New blocks in the middle become
// file holes unless they have been fallocate()'d beforehand.
func (f *File) truncateGrowFile(oldPlainSz uint64, newPlainSz uint64) fuse.Status {
	if newPlainSz <= oldPlainSz {
		log.Panicf("BUG: newSize=%d <= oldSize=%d", newPlainSz, oldPlainSz)
	}
	var n1 uint64
	if oldPlainSz > 0 {
		n1 = f.contentEnc.PlainOffToBlockNo(oldPlainSz - 1)
	}
	newEOFOffset := newPlainSz - 1
	n2 := f.contentEnc.PlainOffToBlockNo(newEOFOffset)
	// The file is grown within one block, no need to pad anything.
	// Write a single zero to the last byte and let doWrite figure out the RMW.
	if n1 == n2 {
		buf := make([]byte, 1)
		_, status := f.doWrite(buf, int64(newEOFOffset))
		return status
	}
	// The truncate creates at least one new block.
	//
	// Make sure the old last block is padded to the block boundary. This call
	// is a no-op if it is already block-aligned.
	f.zeroPad(oldPlainSz)
	// The new size is block-aligned. In this case we can do everything ourselves
	// and avoid the call to doWrite.
	if newPlainSz%f.contentEnc.PlainBS() == 0 {
		// The file was empty, so it did not have a header. Create one.
		if oldPlainSz == 0 {
			f.fileTableEntry.HeaderLock.Lock()
			defer f.fileTableEntry.HeaderLock.Unlock()
			id, err := f.createHeader()
			if err != nil {
				return fuse.ToStatus(err)
			}
			f.fileTableEntry.ID = id
		}
		cSz := int64(f.contentEnc.PlainSizeToCipherSize(newPlainSz))
		err := syscall.Ftruncate(f.intFd(), cSz)
		if err != nil {
			tlog.Warn.Printf("Truncate: grow Ftruncate returned error: %v", err)
		}
		return fuse.ToStatus(err)
	}
	// The new size is NOT aligned, so we need to write a partial block.
	// Write a single zero to the last byte and let doWrite figure it out.
	buf := make([]byte, 1)
	_, status := f.doWrite(buf, int64(newEOFOffset))
	return status
}
