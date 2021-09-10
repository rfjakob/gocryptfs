package fusefrontend

// FUSE operations on file handles

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/inomap"
	"github.com/rfjakob/gocryptfs/v2/internal/openfiletable"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// File implements the go-fuse v2 API (github.com/hanwen/go-fuse/v2/fs)
type File struct {
	fd *os.File
	// Has Release() already been called on this file? This also means that the
	// wlock entry has been freed, so let's not crash trying to access it.
	// Due to concurrency, Release can overtake other operations. These will
	// return EBADF in that case.
	released bool
	// fdLock prevents the fd to be closed while we are in the middle of
	// an operation.
	// Every FUSE entrypoint should RLock(). The only user of Lock() is
	// Release(), which closes the fd and sets "released" to true.
	fdLock sync.RWMutex
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// Device and inode number uniquely identify the backing file
	qIno inomap.QIno
	// Entry in the open file table
	fileTableEntry *openfiletable.Entry
	// Store where the last byte was written
	lastWrittenOffset int64
	// The opCount is used to judge whether "lastWrittenOffset" is still
	// guaranteed to be correct.
	lastOpCount uint64
	// Parent filesystem
	rootNode *RootNode
}

// NewFile returns a new go-fuse File instance based on an already-open file
// descriptor. NewFile internally calls Fstat() on the fd. The resulting Stat_t
// is returned because node.Create() needs it.
//
// `cName` is only used for error logging and may be left blank.
func NewFile(fd int, cName string, rn *RootNode) (f *File, st *syscall.Stat_t, errno syscall.Errno) {
	// Need device number and inode number for openfiletable locking
	st = &syscall.Stat_t{}
	if err := syscall.Fstat(fd, st); err != nil {
		errno = fs.ToErrno(err)
		return
	}
	qi := inomap.QInoFromStat(st)
	e := openfiletable.Register(qi)

	osFile := os.NewFile(uintptr(fd), cName)

	f = &File{
		fd:             osFile,
		contentEnc:     rn.contentEnc,
		qIno:           qi,
		fileTableEntry: e,
		rootNode:       rn,
	}
	return f, st, 0
}

// intFd - return the backing file descriptor as an integer.
func (f *File) intFd() int {
	return int(f.fd.Fd())
}

// readFileID loads the file header from disk and extracts the file ID.
// Returns io.EOF if the file is empty.
func (f *File) readFileID() ([]byte, error) {
	// We read +1 byte to determine if the file has actual content
	// and not only the header. A header-only file will be considered empty.
	// This makes File ID poisoning more difficult.
	readLen := contentenc.HeaderLen + 1
	buf := make([]byte, readLen)
	n, err := f.fd.ReadAt(buf, 0)
	if err != nil {
		if err == io.EOF && n != 0 {
			tlog.Warn.Printf("readFileID %d: incomplete file, got %d instead of %d bytes",
				f.qIno.Ino, n, readLen)
			f.rootNode.reportMitigatedCorruption(fmt.Sprint(f.qIno.Ino))
		}
		return nil, err
	}
	buf = buf[:contentenc.HeaderLen]
	h, err := contentenc.ParseHeader(buf)
	if err != nil {
		return nil, err
	}
	return h.ID, nil
}

// createHeader creates a new random header and writes it to disk.
// Returns the new file ID.
// The caller must hold fileIDLock.Lock().
func (f *File) createHeader() (fileID []byte, err error) {
	h := contentenc.RandomHeader()
	buf := h.Pack()
	// Prevent partially written (=corrupt) header by preallocating the space beforehand
	if !f.rootNode.args.NoPrealloc && f.rootNode.quirks&syscallcompat.QuirkBrokenFalloc == 0 {
		err = syscallcompat.EnospcPrealloc(f.intFd(), 0, contentenc.HeaderLen)
		if err != nil {
			if !syscallcompat.IsENOSPC(err) {
				tlog.Warn.Printf("ino%d: createHeader: prealloc failed: %s\n", f.qIno.Ino, err.Error())
			}
			return nil, err
		}
	}
	// Actually write header
	_, err = f.fd.WriteAt(buf, 0)
	if err != nil {
		return nil, err
	}
	return h.ID, err
}

// doRead - read "length" plaintext bytes from plaintext offset "off" and append
// to "dst".
// Arguments "length" and "off" do not have to be block-aligned.
//
// doRead reads the corresponding ciphertext blocks from disk, decrypts them and
// returns the requested part of the plaintext.
//
// Called by Read() for normal reading,
// by Write() and Truncate() via doWrite() for Read-Modify-Write.
func (f *File) doRead(dst []byte, off uint64, length uint64) ([]byte, syscall.Errno) {
	// Get the file ID, either from the open file table, or from disk.
	var fileID []byte
	f.fileTableEntry.IDLock.Lock()
	if f.fileTableEntry.ID != nil {
		// Use the cached value in the file table
		fileID = f.fileTableEntry.ID
	} else {
		// Not cached, we have to read it from disk.
		var err error
		fileID, err = f.readFileID()
		if err != nil {
			f.fileTableEntry.IDLock.Unlock()
			if err == io.EOF {
				// Empty file
				return nil, 0
			}
			buf := make([]byte, 100)
			n, _ := f.fd.ReadAt(buf, 0)
			buf = buf[:n]
			hexdump := hex.EncodeToString(buf)
			tlog.Warn.Printf("doRead %d: corrupt header: %v\nFile hexdump (%d bytes): %s",
				f.qIno.Ino, err, n, hexdump)
			return nil, syscall.EIO
		}
		// Save into the file table
		f.fileTableEntry.ID = fileID
	}
	f.fileTableEntry.IDLock.Unlock()
	if fileID == nil {
		log.Panicf("fileID=%v", fileID)
	}
	// Read the backing ciphertext in one go
	blocks := f.contentEnc.ExplodePlainRange(off, length)
	alignedOffset, alignedLength := blocks[0].JointCiphertextRange(blocks)
	// f.fd.ReadAt takes an int64!
	if alignedOffset > math.MaxInt64 {
		return nil, syscall.EFBIG
	}
	skip := blocks[0].Skip
	tlog.Debug.Printf("doRead: off=%d len=%d -> off=%d len=%d skip=%d\n",
		off, length, alignedOffset, alignedLength, skip)

	ciphertext := f.rootNode.contentEnc.CReqPool.Get()
	ciphertext = ciphertext[:int(alignedLength)]
	n, err := f.fd.ReadAt(ciphertext, int64(alignedOffset))
	if err != nil && err != io.EOF {
		tlog.Warn.Printf("read: ReadAt: %s", err.Error())
		return nil, fs.ToErrno(err)
	}
	// The ReadAt came back empty. We can skip all the decryption and return early.
	if n == 0 {
		f.rootNode.contentEnc.CReqPool.Put(ciphertext)
		return dst, 0
	}
	// Truncate ciphertext buffer down to actually read bytes
	ciphertext = ciphertext[0:n]

	firstBlockNo := blocks[0].BlockNo
	tlog.Debug.Printf("ReadAt offset=%d bytes (%d blocks), want=%d, got=%d", alignedOffset, firstBlockNo, alignedLength, n)

	// Decrypt it
	plaintext, err := f.contentEnc.DecryptBlocks(ciphertext, firstBlockNo, fileID)
	f.rootNode.contentEnc.CReqPool.Put(ciphertext)
	if err != nil {
		curruptBlockNo := firstBlockNo + f.contentEnc.PlainOffToBlockNo(uint64(len(plaintext)))
		tlog.Warn.Printf("doRead %d: corrupt block #%d: %v", f.qIno.Ino, curruptBlockNo, err)
		return nil, syscall.EIO
	}

	// Crop down to the relevant part
	var out []byte
	lenHave := len(plaintext)
	lenWant := int(skip + length)
	if lenHave > lenWant {
		out = plaintext[skip:lenWant]
	} else if lenHave > int(skip) {
		out = plaintext[skip:lenHave]
	}
	// else: out stays empty, file was smaller than the requested offset

	out = append(dst, out...)
	f.rootNode.contentEnc.PReqPool.Put(plaintext)

	return out, 0
}

// Read - FUSE call
func (f *File) Read(ctx context.Context, buf []byte, off int64) (resultData fuse.ReadResult, errno syscall.Errno) {
	if len(buf) > fuse.MAX_KERNEL_WRITE {
		// This would crash us due to our fixed-size buffer pool
		tlog.Warn.Printf("Read: rejecting oversized request with EMSGSIZE, len=%d", len(buf))
		return nil, syscall.EMSGSIZE
	}
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	f.fileTableEntry.ContentLock.RLock()
	defer f.fileTableEntry.ContentLock.RUnlock()

	tlog.Debug.Printf("ino%d: FUSE Read: offset=%d length=%d", f.qIno.Ino, off, len(buf))
	out, errno := f.doRead(buf[:0], uint64(off), uint64(len(buf)))
	if errno != 0 {
		return nil, errno
	}
	tlog.Debug.Printf("ino%d: Read: errno=%d, returning %d bytes", f.qIno.Ino, errno, len(out))
	return fuse.ReadResultData(out), errno
}

// doWrite - encrypt "data" and write it to plaintext offset "off"
//
// Arguments do not have to be block-aligned, read-modify-write is
// performed internally as necessary
//
// Called by Write() for normal writing,
// and by Truncate() to rewrite the last file block.
//
// Empty writes do nothing and are allowed.
func (f *File) doWrite(data []byte, off int64) (uint32, syscall.Errno) {
	fileWasEmpty := false
	// The caller has exclusively locked ContentLock, which blocks all other
	// readers and writers. No need to take IDLock.
	//
	// If the file ID is not cached, read it from disk
	if f.fileTableEntry.ID == nil {
		var err error
		fileID, err := f.readFileID()
		// Write a new file header if the file is empty
		if err == io.EOF {
			fileID, err = f.createHeader()
			fileWasEmpty = true
		}
		if err != nil {
			return 0, fs.ToErrno(err)
		}
		f.fileTableEntry.ID = fileID
	}
	// Handle payload data
	dataBuf := bytes.NewBuffer(data)
	blocks := f.contentEnc.ExplodePlainRange(uint64(off), uint64(len(data)))
	toEncrypt := make([][]byte, len(blocks))
	for i, b := range blocks {
		blockData := dataBuf.Next(int(b.Length))
		// Incomplete block -> Read-Modify-Write
		if b.IsPartial() {
			// Read
			oldData, errno := f.doRead(nil, b.BlockPlainOff(), f.contentEnc.PlainBS())
			if errno != 0 {
				tlog.Warn.Printf("ino%d fh%d: RMW read failed: errno=%d", f.qIno.Ino, f.intFd(), errno)
				return 0, errno
			}
			// Modify
			blockData = f.contentEnc.MergeBlocks(oldData, blockData, int(b.Skip))
			tlog.Debug.Printf("len(oldData)=%d len(blockData)=%d", len(oldData), len(blockData))
		}
		tlog.Debug.Printf("ino%d: Writing %d bytes to block #%d",
			f.qIno.Ino, len(blockData), b.BlockNo)
		// Write into the to-encrypt list
		toEncrypt[i] = blockData
	}
	// Encrypt all blocks
	ciphertext := f.contentEnc.EncryptBlocks(toEncrypt, blocks[0].BlockNo, f.fileTableEntry.ID)
	// Preallocate so we cannot run out of space in the middle of the write.
	// This prevents partially written (=corrupt) blocks.
	var err error
	cOff := blocks[0].BlockCipherOff()
	// f.fd.WriteAt & syscallcompat.EnospcPrealloc take int64 offsets!
	if cOff > math.MaxInt64 {
		return 0, syscall.EFBIG
	}
	if !f.rootNode.args.NoPrealloc {
		err = syscallcompat.EnospcPrealloc(f.intFd(), int64(cOff), int64(len(ciphertext)))
		if err != nil {
			if !syscallcompat.IsENOSPC(err) {
				tlog.Warn.Printf("ino%d fh%d: doWrite: prealloc failed: %v", f.qIno.Ino, f.intFd(), err)
			}
			if fileWasEmpty {
				// Kill the file header again
				f.fileTableEntry.ID = nil
				err2 := syscall.Ftruncate(f.intFd(), 0)
				if err2 != nil {
					tlog.Warn.Printf("ino%d fh%d: doWrite: rollback failed: %v", f.qIno.Ino, f.intFd(), err2)
				}
			}
			return 0, fs.ToErrno(err)
		}
	}
	// Write
	_, err = f.fd.WriteAt(ciphertext, int64(cOff))
	// Return memory to CReqPool
	f.rootNode.contentEnc.CReqPool.Put(ciphertext)
	if err != nil {
		tlog.Warn.Printf("ino%d fh%d: doWrite: WriteAt off=%d len=%d failed: %v",
			f.qIno.Ino, f.intFd(), cOff, len(ciphertext), err)
		return 0, fs.ToErrno(err)
	}
	return uint32(len(data)), 0
}

// isConsecutiveWrite returns true if the current write
// directly (in time and space) follows the last write.
// This is an optimisation for streaming writes on NFS where a
// Stat() call is very expensive.
// The caller must "wlock.lock(f.devIno.ino)" otherwise this check would be racy.
func (f *File) isConsecutiveWrite(off int64) bool {
	opCount := openfiletable.WriteOpCount()
	return opCount == f.lastOpCount+1 && off == f.lastWrittenOffset+1
}

// Write - FUSE call
//
// If the write creates a hole, pads the file to the next block boundary.
func (f *File) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	if len(data) > fuse.MAX_KERNEL_WRITE {
		// This would crash us due to our fixed-size buffer pool
		tlog.Warn.Printf("Write: rejecting oversized request with EMSGSIZE, len=%d", len(data))
		return 0, syscall.EMSGSIZE
	}
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	if f.released {
		// The file descriptor has been closed concurrently
		tlog.Warn.Printf("ino%d fh%d: Write on released file", f.qIno.Ino, f.intFd())
		return 0, syscall.EBADF
	}
	f.fileTableEntry.ContentLock.Lock()
	defer f.fileTableEntry.ContentLock.Unlock()
	tlog.Debug.Printf("ino%d: FUSE Write: offset=%d length=%d", f.qIno.Ino, off, len(data))
	// If the write creates a file hole, we have to zero-pad the last block.
	// But if the write directly follows an earlier write, it cannot create a
	// hole, and we can save one Stat() call.
	if !f.isConsecutiveWrite(off) {
		errno := f.writePadHole(off)
		if errno != 0 {
			return 0, errno
		}
	}
	n, errno := f.doWrite(data, off)
	if errno != 0 {
		f.lastOpCount = openfiletable.WriteOpCount()
		f.lastWrittenOffset = off + int64(len(data)) - 1
	}
	return n, errno
}

// Release - FUSE call, close file
func (f *File) Release(ctx context.Context) syscall.Errno {
	f.fdLock.Lock()
	if f.released {
		log.Panicf("ino%d fh%d: double release", f.qIno.Ino, f.intFd())
	}
	f.released = true
	openfiletable.Unregister(f.qIno)
	err := f.fd.Close()
	f.fdLock.Unlock()
	return fs.ToErrno(err)
}

// Flush - FUSE call
func (f *File) Flush(ctx context.Context) syscall.Errno {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	err := syscallcompat.Flush(f.intFd())
	return fs.ToErrno(err)
}

// Fsync: handles FUSE opcode FSYNC
//
// Unfortunately, as Node.Fsync is also defined and takes precedence,
// File.Fsync is never called at the moment.
func (f *File) Fsync(ctx context.Context, flags uint32) (errno syscall.Errno) {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	return fs.ToErrno(syscall.Fsync(f.intFd()))
}

// Getattr FUSE call (like stat)
func (f *File) Getattr(ctx context.Context, a *fuse.AttrOut) syscall.Errno {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	tlog.Debug.Printf("file.GetAttr()")
	st := syscall.Stat_t{}
	err := syscall.Fstat(f.intFd(), &st)
	if err != nil {
		return fs.ToErrno(err)
	}
	f.rootNode.inoMap.TranslateStat(&st)
	a.FromStat(&st)
	a.Size = f.contentEnc.CipherSizeToPlainSize(a.Size)
	if f.rootNode.args.ForceOwner != nil {
		a.Owner = *f.rootNode.args.ForceOwner
	}

	return 0
}
