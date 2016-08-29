package fusefrontend_reverse

import (
	"fmt"
	"io"
	"os"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

var zeroFileId []byte

func init() {
	zeroFileId = make([]byte, 16)
}

type reverseFile struct {
	// Embed nodefs.defaultFile for a ENOSYS implementation of all methods
	nodefs.File
	// Backing FD
	fd *os.File
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
}

func NewFile(fd *os.File, contentEnc *contentenc.ContentEnc) (nodefs.File, fuse.Status) {
	return &reverseFile{
		File:       nodefs.NewDefaultFile(),
		fd:         fd,
		contentEnc: contentEnc,
	}, fuse.OK
}

// GetAttr - FUSE call
func (rf *reverseFile) GetAttr(*fuse.Attr) fuse.Status {
	fmt.Printf("reverseFile.GetAttr fd=%d\n", rf.fd.Fd())
	return fuse.ENOSYS
}

// Read - FUSE call
func (rf *reverseFile) Read(buf []byte, off int64) (resultData fuse.ReadResult, status fuse.Status) {
	// TODO prefix file header

	length := uint64(len(buf))
	blocks := rf.contentEnc.ExplodeCipherRange(uint64(off), length)

	// Read the backing plaintext in one go
	alignedOffset, alignedLength := contentenc.JointPlaintextRange(blocks)
	tlog.Warn.Printf("alignedOffset=%d, alignedLength=%d\n", alignedOffset, alignedLength)
	plaintext := make([]byte, int(alignedLength))
	n, err := rf.fd.ReadAt(plaintext, int64(alignedOffset))
	if err != nil && err != io.EOF {
		tlog.Warn.Printf("reverseFile.Read: ReadAt: %s", err.Error())
		return nil, fuse.ToStatus(err)
	}
	// Truncate buffer down to actually read bytes
	plaintext = plaintext[0:n]

	// Encrypt blocks
	ciphertext := rf.contentEnc.EncryptBlocks(plaintext, blocks[0].BlockNo, zeroFileId)

	// Crop down to the relevant part
	var out []byte
	lenHave := len(ciphertext)
	skip := blocks[0].Skip
	endWant := int(skip + length)
	if lenHave > endWant {
		out = plaintext[skip:endWant]
	} else if lenHave > int(skip) {
		out = plaintext[skip:lenHave]
	}
	// else: out stays empty, file was smaller than the requested offset

	return fuse.ReadResultData(out), fuse.OK
}
