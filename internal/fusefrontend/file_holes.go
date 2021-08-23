package fusefrontend

// Helper functions for sparse files (files with holes)

import (
	"context"
	"runtime"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
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
//
// Looking at
// fuse_file_llseek @ https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/fs/fuse/file.c?h=v5.12.7#n2634
// this function is only called for SEEK_HOLE & SEEK_DATA.
func (f *File) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	const (
		SEEK_DATA = 3 // find next data segment at or above `off`
		SEEK_HOLE = 4 // find next hole at or above `off`

		// On error, we return -1 as the offset as per man lseek.
		MinusOne = ^uint64(0)
	)
	if whence != SEEK_DATA && whence != SEEK_HOLE {
		tlog.Warn.Printf("BUG: Lseek was called with whence=%d. This is not supported!", whence)
		return 0, syscall.EINVAL
	}
	if runtime.GOOS != "linux" {
		// MacOS has broken (different?) SEEK_DATA / SEEK_HOLE semantics, see
		// https://lists.gnu.org/archive/html/bug-gnulib/2018-09/msg00051.html
		tlog.Warn.Printf("buggy on non-linux platforms, disabling SEEK_DATA & SEEK_HOLE")
		return MinusOne, syscall.ENOSYS
	}

	// We will need the file size
	var st syscall.Stat_t
	err := syscall.Fstat(f.intFd(), &st)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	fileSize := st.Size
	// Better safe than sorry. The logic is only tested for 4k blocks.
	if st.Blksize != 4096 {
		tlog.Warn.Printf("unsupported block size of %d bytes, disabling SEEK_DATA & SEEK_HOLE", st.Blksize)
		return MinusOne, syscall.ENOSYS
	}

	// man lseek: offset beyond end of file -> ENXIO
	if f.rootNode.contentEnc.PlainOffToCipherOff(off) >= uint64(fileSize) {
		return MinusOne, syscall.ENXIO
	}

	// Round down to start of block:
	cipherOff := f.rootNode.contentEnc.BlockNoToCipherOff(f.rootNode.contentEnc.PlainOffToBlockNo(off))
	newCipherOff, err := syscall.Seek(f.intFd(), int64(cipherOff), int(whence))
	if err != nil {
		return MinusOne, fs.ToErrno(err)
	}
	// already in data/hole => return original offset
	if newCipherOff == int64(cipherOff) {
		return off, 0
	}
	// If there is no further hole, SEEK_HOLE returns the file size
	// (SEEK_DATA returns ENXIO in this case).
	if whence == SEEK_HOLE {
		fi, err := f.fd.Stat()
		if err != nil {
			return MinusOne, fs.ToErrno(err)
		}
		if newCipherOff == fi.Size() {
			return f.rootNode.contentEnc.CipherSizeToPlainSize(uint64(newCipherOff)), 0
		}
	}
	// syscall.Seek gave us the beginning of the next ext4 data/hole section.
	// The next gocryptfs data/hole block starts at the next block boundary,
	// so we have to round up:
	newBlockNo := f.rootNode.contentEnc.CipherOffToBlockNo(uint64(newCipherOff) + f.rootNode.contentEnc.CipherBS() - 1)
	return f.rootNode.contentEnc.BlockNoToPlainOff(newBlockNo), 0
}
