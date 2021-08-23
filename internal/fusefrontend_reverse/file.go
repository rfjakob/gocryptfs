package fusefrontend_reverse

import (
	"bytes"
	"context"
	"os"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
)

type File struct {
	// Backing FD
	fd *os.File
	// File header (contains the IV)
	header contentenc.FileHeader
	// IV for block 0
	block0IV []byte
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
}

// Read - FUSE call
func (f *File) Read(ctx context.Context, buf []byte, ioff int64) (resultData fuse.ReadResult, errno syscall.Errno) {
	length := uint64(len(buf))
	off := uint64(ioff)
	out := bytes.NewBuffer(buf[:0])
	var header []byte

	// Synthesize file header
	if off < contentenc.HeaderLen {
		header = f.header.Pack()
		// Truncate to requested part
		end := int(off) + len(buf)
		if end > len(header) {
			end = len(header)
		}
		header = header[off:end]
		// Write into output buffer and adjust offsets
		out.Write(header)
		hLen := uint64(len(header))
		off += hLen
		length -= hLen
	}

	// Read actual file data
	if length > 0 {
		fileData, err := f.readBackingFile(off, length)
		if err != nil {
			return nil, fs.ToErrno(err)
		}
		if len(fileData) == 0 {
			// If we could not read any actual data, we also don't want to
			// return the file header. An empty file stays empty in encrypted
			// form.
			return nil, 0
		}
		out.Write(fileData)
	}

	return fuse.ReadResultData(out.Bytes()), 0
}

// Release - FUSE call, close file
func (f *File) Release(context.Context) syscall.Errno {
	return fs.ToErrno(f.fd.Close())
}

// Lseek - FUSE call.
func (f *File) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	plainOff := f.contentEnc.CipherSizeToPlainSize(off)
	newPlainOff, err := syscall.Seek(int(f.fd.Fd()), int64(plainOff), int(whence))
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	newOff := f.contentEnc.PlainSizeToCipherSize(uint64(newPlainOff))
	return newOff, 0
}
