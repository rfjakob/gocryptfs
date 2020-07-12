package fusefrontend

// Helper functions for sparse files (files with holes)

import (
	"runtime"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Will a write to plaintext offset "targetOff" create a file hole in the
// ciphertext? If yes, zero-pad the last ciphertext block.
func (f *File2) writePadHole(targetOff int64) syscall.Errno {
	// Get the current file size.
	fi, err := f.fd.Stat()
	if err != nil {
		tlog.Warn.Printf("checkAndPadHole: Fstat failed: %v", err)
		return fs.ToErrno(err)
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
		return 0
	}
	// The write goes past the next block. nextBlock has
	// to be zero-padded to the block boundary and (at least) nextBlock+1
	// will contain a file hole in the ciphertext.
	errno := f.zeroPad(plainSize)
	if errno != 0 {
		return errno
	}
	return 0
}

// Zero-pad the file of size plainSize to the next block boundary. This is a no-op
// if the file is already block-aligned.
func (f *File2) zeroPad(plainSize uint64) syscall.Errno {
	lastBlockLen := plainSize % f.contentEnc.PlainBS()
	if lastBlockLen == 0 {
		// Already block-aligned
		return 0
	}
	missing := f.contentEnc.PlainBS() - lastBlockLen
	pad := make([]byte, missing)
	tlog.Debug.Printf("zeroPad: Writing %d bytes\n", missing)
	_, errno := f.doWrite(pad, int64(plainSize))
	return errno
}

// SeekData calls the lseek syscall with SEEK_DATA. It returns the offset of the
// next data bytes, skipping over file holes.
func (f *File2) SeekData(oldOffset int64) (int64, error) {
	if runtime.GOOS != "linux" {
		// Does MacOS support something like this?
		return 0, syscall.EOPNOTSUPP
	}
	const SEEK_DATA = 3

	// Convert plaintext offset to ciphertext offset and round down to the
	// start of the current block. File holes smaller than a full block will
	// be ignored.
	blockNo := f.contentEnc.PlainOffToBlockNo(uint64(oldOffset))
	oldCipherOff := int64(f.contentEnc.BlockNoToCipherOff(blockNo))

	// Determine the next data offset. If the old offset points to (or beyond)
	// the end of the file, the Seek syscall fails with syscall.ENXIO.
	newCipherOff, err := syscall.Seek(f.intFd(), oldCipherOff, SEEK_DATA)
	if err != nil {
		return 0, err
	}

	// Convert ciphertext offset back to plaintext offset. At this point,
	// newCipherOff should always be >= contentenc.HeaderLen. Round down,
	// but ensure that the result is never smaller than the initial offset
	// (to avoid endless loops).
	blockNo = f.contentEnc.CipherOffToBlockNo(uint64(newCipherOff))
	newOffset := int64(f.contentEnc.BlockNoToPlainOff(blockNo))
	if newOffset < oldOffset {
		newOffset = oldOffset
	}

	return newOffset, nil
}
