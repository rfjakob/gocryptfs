package fusefrontend_reverse

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"syscall"

	// In newer Go versions, this has moved to just "sync/syncmap".
	"golang.org/x/sync/syncmap"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
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

var inodeTable syncmap.Map

// newFile receives a ciphered path "relPath" and its corresponding
// decrypted path "pRelPath", opens it and returns a reverseFile
// object. The backing file descriptor is always read-only.
func (rfs *ReverseFS) newFile(relPath string, pRelPath string) (*reverseFile, fuse.Status) {
	if rfs.isExcludedPlain(pRelPath) {
		// Excluded paths should have been filtered out beforehand. Better safe
		// than sorry.
		tlog.Warn.Printf("BUG: newFile: received excluded path %q. This should not happen.", relPath)
		return nil, fuse.ENOENT
	}
	dir := filepath.Dir(pRelPath)
	dirfd, err := syscallcompat.OpenDirNofollow(rfs.args.Cipherdir, dir)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	fd, err := syscallcompat.Openat(dirfd, filepath.Base(pRelPath), syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	syscall.Close(dirfd)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	var st syscall.Stat_t
	err = syscall.Fstat(fd, &st)
	if err != nil {
		tlog.Warn.Printf("newFile: Fstat error: %v", err)
		syscall.Close(fd)
		return nil, fuse.ToStatus(err)
	}
	// Reject access if the file descriptor does not refer to a regular file.
	var a fuse.Attr
	a.FromStat(&st)
	if !a.IsRegular() {
		tlog.Warn.Printf("ino%d: newFile: not a regular file", st.Ino)
		syscall.Close(fd)
		return nil, fuse.ToStatus(syscall.EACCES)
	}
	// See if we have that inode number already in the table
	// (even if Nlink has dropped to 1)
	var derivedIVs pathiv.FileIVs
	v, found := inodeTable.Load(st.Ino)
	if found {
		tlog.Debug.Printf("ino%d: newFile: found in the inode table", st.Ino)
		derivedIVs = v.(pathiv.FileIVs)
	} else {
		derivedIVs = pathiv.DeriveFile(relPath)
		// Nlink > 1 means there is more than one path to this file.
		// Store the derived values so we always return the same data,
		// regardless of the path that is used to access the file.
		// This means that the first path wins.
		if st.Nlink > 1 {
			v, found = inodeTable.LoadOrStore(st.Ino, derivedIVs)
			if found {
				// Another thread has stored a different value before we could.
				derivedIVs = v.(pathiv.FileIVs)
			} else {
				tlog.Debug.Printf("ino%d: newFile: Nlink=%d, stored in the inode table", st.Ino, st.Nlink)
			}
		}
	}
	header := contentenc.FileHeader{
		Version: contentenc.CurrentVersion,
		ID:      derivedIVs.ID,
	}
	return &reverseFile{
		File:       nodefs.NewDefaultFile(),
		fd:         os.NewFile(uintptr(fd), pRelPath),
		header:     header,
		block0IV:   derivedIVs.Block0IV,
		contentEnc: rfs.contentEnc,
	}, fuse.OK
}

// GetAttr - FUSE call
// Triggered by fstat() from userspace
func (rf *reverseFile) GetAttr(*fuse.Attr) fuse.Status {
	tlog.Debug.Printf("reverseFile.GetAttr fd=%d\n", rf.fd.Fd())
	// The kernel should fall back to stat()
	return fuse.ENOSYS
}

// encryptBlocks - encrypt "plaintext" into a number of ciphertext blocks.
// "plaintext" must already be block-aligned.
func (rf *reverseFile) encryptBlocks(plaintext []byte, firstBlockNo uint64, fileID []byte, block0IV []byte) []byte {
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
