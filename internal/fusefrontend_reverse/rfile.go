package fusefrontend_reverse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

type reverseFile struct {
	// Embed nodefs.defaultFile for a ENOSYS implementation of all methods
	nodefs.File
	// Backing FD
	fd *os.File
	// File header (contains the IV)
	header contentenc.FileHeader
	// IV for block 0
	block0IV []byte
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
}

func (rfs *ReverseFS) newFile(relPath string, flags uint32) (nodefs.File, fuse.Status) {
	absPath, err := rfs.abs(rfs.decryptPath(relPath))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	fd, err := os.OpenFile(absPath, int(flags), 0666)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	id := derivePathIV(relPath, ivPurposeFileID)
	header := contentenc.FileHeader{
		Version: contentenc.CurrentVersion,
		ID:      id,
	}
	return &reverseFile{
		File:       nodefs.NewDefaultFile(),
		fd:         fd,
		header:     header,
		block0IV:   derivePathIV(relPath, ivPurposeBlock0IV),
		contentEnc: rfs.contentEnc,
	}, fuse.OK
}

// GetAttr - FUSE call
func (rf *reverseFile) GetAttr(*fuse.Attr) fuse.Status {
	fmt.Printf("reverseFile.GetAttr fd=%d\n", rf.fd.Fd())
	return fuse.ENOSYS
}

// encryptBlocks - encrypt "plaintext" into a number of ciphertext blocks.
// "plaintext" must already be block-aligned.
func (rf *reverseFile) encryptBlocks(plaintext []byte, firstBlockNo uint64, fileID []byte, block0IV []byte) []byte {
	nonce := make([]byte, len(block0IV))
	copy(nonce, block0IV)
	block0IVlow := binary.BigEndian.Uint64(block0IV[8:])
	nonceLow := nonce[8:]

	inBuf := bytes.NewBuffer(plaintext)
	var outBuf bytes.Buffer
	bs := int(rf.contentEnc.PlainBS())
	for blockNo := firstBlockNo; inBuf.Len() > 0; blockNo++ {
		binary.BigEndian.PutUint64(nonceLow, block0IVlow+blockNo)
		inBlock := inBuf.Next(bs)
		outBlock := rf.contentEnc.EncryptBlockNonce(inBlock, blockNo, fileID, nonce)
		outBuf.Write(outBlock)
	}
	return outBuf.Bytes()
}

// readBackingFile: read from the backing plaintext file, encrypt it, return the
// ciphertext.
// "off" ... ciphertext offset (must be >= HEADER_LEN)
// "length" ... ciphertext length
func (rf *reverseFile) readBackingFile(off uint64, length uint64) (out []byte, err error) {
	blocks := rf.contentEnc.ExplodeCipherRange(off, length)

	// Read the backing plaintext in one go
	alignedOffset, alignedLength := contentenc.JointPlaintextRange(blocks)
	plaintext := make([]byte, int(alignedLength))
	n, err := rf.fd.ReadAt(plaintext, int64(alignedOffset))
	if err != nil && err != io.EOF {
		tlog.Warn.Printf("readBackingFile: ReadAt: %s", err.Error())
		return nil, err
	}
	// Truncate buffer down to actually read bytes
	plaintext = plaintext[0:n]

	// Encrypt blocks
	ciphertext := rf.encryptBlocks(plaintext, blocks[0].BlockNo, rf.header.ID, rf.block0IV)

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

// Read - FUSE call
func (rf *reverseFile) Read(buf []byte, ioff int64) (resultData fuse.ReadResult, status fuse.Status) {
	length := uint64(len(buf))
	off := uint64(ioff)
	var out bytes.Buffer
	var header []byte

	// Synthesize file header
	if off < contentenc.HeaderLen {
		header = rf.header.Pack()
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
		fileData, err := rf.readBackingFile(off, length)
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
		if len(fileData) == 0 {
			// If we could not read any actual data, we also don't want to
			// return the file header. An empty file stays empty in encrypted
			// form.
			return nil, fuse.OK
		}
		out.Write(fileData)
	}

	return fuse.ReadResultData(out.Bytes()), fuse.OK
}

// Release - FUSE call, close file
func (rf *reverseFile) Release() {
	rf.fd.Close()
}
