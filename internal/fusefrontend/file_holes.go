package fusefrontend

// Helper functions for sparse files (files with holes)

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Will a write to plaintext offset "targetOff" create a file hole in the
// ciphertext? If yes, zero-pad the last ciphertext block.
func (f *File) writePadHole(targetOff int64) syscall.Errno {
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
func (f *File) zeroPad(plainSize uint64) syscall.Errno {
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

// Lseek - FUSE call.
func (f *File) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	cipherOff := f.rootNode.contentEnc.PlainSizeToCipherSize(off)
	newCipherOff, err := syscall.Seek(f.intFd(), int64(cipherOff), int(whence))
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	newOff := f.contentEnc.CipherSizeToPlainSize(uint64(newCipherOff))
	return newOff, 0
}
