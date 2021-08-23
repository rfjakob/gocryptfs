package fusefrontend_reverse

import (
	"bytes"
	"io"
	"sync"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/pathiv"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var inodeTable sync.Map

// encryptBlocks - encrypt "plaintext" into a number of ciphertext blocks.
// "plaintext" must already be block-aligned.
func (rf *File) encryptBlocks(plaintext []byte, firstBlockNo uint64, fileID []byte, block0IV []byte) []byte {
	inBuf := bytes.NewBuffer(plaintext)
	var outBuf bytes.Buffer
	bs := int(rf.contentEnc.PlainBS())
	for blockNo := firstBlockNo; inBuf.Len() > 0; blockNo++ {
		inBlock := inBuf.Next(bs)
		iv := pathiv.BlockIV(block0IV, blockNo)
		outBlock := rf.contentEnc.EncryptBlockNonce(inBlock, blockNo, fileID, iv)
		outBuf.Write(outBlock)
	}
	return outBuf.Bytes()
}

// readBackingFile: read from the backing plaintext file, encrypt it, return the
// ciphertext.
// "off" ... ciphertext offset (must be >= HEADER_LEN)
// "length" ... ciphertext length
func (f *File) readBackingFile(off uint64, length uint64) (out []byte, err error) {
	blocks := f.contentEnc.ExplodeCipherRange(off, length)

	// Read the backing plaintext in one go
	alignedOffset, alignedLength := contentenc.JointPlaintextRange(blocks)
	plaintext := make([]byte, int(alignedLength))
	n, err := f.fd.ReadAt(plaintext, int64(alignedOffset))
	if err != nil && err != io.EOF {
		tlog.Warn.Printf("readBackingFile: ReadAt: %s", err.Error())
		return nil, err
	}
	// Truncate buffer down to actually read bytes
	plaintext = plaintext[0:n]

	// Encrypt blocks
	ciphertext := f.encryptBlocks(plaintext, blocks[0].BlockNo, f.header.ID, f.block0IV)

	// Crop down to the relevant part
	lenHave := len(ciphertext)
	skip := blocks[0].Skip
	endWant := int(skip + length)
	if lenHave > endWant {
		out = ciphertext[skip:endWant]
	} else if lenHave > int(skip) {
		out = ciphertext[skip:lenHave]
	} // else: out stays empty, file was smaller than the requested offset

	return out, nil
}
