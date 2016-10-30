package fusefrontend

// FUSE operations on file handles

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// File - based on loopbackFile in go-fuse/fuse/nodefs/files.go
type file struct {
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
	// Was the file opened O_WRONLY?
	writeOnly bool
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// Inode number
	ino uint64
	// File header
	header *contentenc.FileHeader
	// go-fuse nodefs.loopbackFile
	loopbackFile nodefs.File
	// Store what the last byte was written
	lastWrittenOffset int64
	// The opCount is used to judge whether "lastWrittenOffset" is still
	// guaranteed to be correct.
	lastOpCount uint64
}

// NewFile returns a new go-fuse File instance.
func NewFile(fd *os.File, writeOnly bool, contentEnc *contentenc.ContentEnc) (nodefs.File, fuse.Status) {
	var st syscall.Stat_t
	err := syscall.Fstat(int(fd.Fd()), &st)
	if err != nil {
		tlog.Warn.Printf("NewFile: Fstat on fd %d failed: %v\n", fd.Fd(), err)
		return nil, fuse.ToStatus(err)
	}
	wlock.register(st.Ino)

	return &file{
		fd:           fd,
		writeOnly:    writeOnly,
		contentEnc:   contentEnc,
		ino:          st.Ino,
		loopbackFile: nodefs.NewLoopbackFile(fd),
	}, fuse.OK
}

// intFd - return the backing file descriptor as an integer. Used for debug
// messages.
func (f *file) intFd() int {
	return int(f.fd.Fd())
}

func (f *file) InnerFile() nodefs.File {
	return nil
}

func (f *file) SetInode(n *nodefs.Inode) {
}

// readHeader - load the file header from disk
//
// Returns io.EOF if the file is empty
func (f *file) readHeader() error {
	buf := make([]byte, contentenc.HeaderLen)
	_, err := f.fd.ReadAt(buf, 0)
	if err != nil {
		return err
	}
	h, err := contentenc.ParseHeader(buf)
	if err != nil {
		return err
	}
	f.header = h

	return nil
}

// createHeader - create a new random header and write it to disk
func (f *file) createHeader() error {
	h := contentenc.RandomHeader()
	buf := h.Pack()

	// Prevent partially written (=corrupt) header by preallocating the space beforehand
	err := syscallcompat.EnospcPrealloc(int(f.fd.Fd()), 0, contentenc.HeaderLen)
	if err != nil {
		tlog.Warn.Printf("ino%d: createHeader: prealloc failed: %s\n", f.ino, err.Error())
		return err
	}

	// Actually write header
	_, err = f.fd.WriteAt(buf, 0)
	if err != nil {
		return err
	}
	f.header = h

	return nil
}

func (f *file) String() string {
	return fmt.Sprintf("cryptFile(%s)", f.fd.Name())
}

// doRead - returns "length" plaintext bytes from plaintext offset "off".
// Arguments "length" and "off" do not have to be block-aligned.
//
// doRead reads the corresponding ciphertext blocks from disk, decrypts them and
// returns the requested part of the plaintext.
//
// Called by Read() for normal reading,
// by Write() and Truncate() for Read-Modify-Write
func (f *file) doRead(off uint64, length uint64) ([]byte, fuse.Status) {

	// Read file header
	if f.header == nil {
		err := f.readHeader()
		if err == io.EOF {
			return nil, fuse.OK
		}
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
	}

	// Read the backing ciphertext in one go
	blocks := f.contentEnc.ExplodePlainRange(off, length)
	alignedOffset, alignedLength := blocks[0].JointCiphertextRange(blocks)
	skip := blocks[0].Skip
	tlog.Debug.Printf("JointCiphertextRange(%d, %d) -> %d, %d, %d", off, length, alignedOffset, alignedLength, skip)
	ciphertext := make([]byte, int(alignedLength))
	n, err := f.fd.ReadAt(ciphertext, int64(alignedOffset))
	if err != nil && err != io.EOF {
		tlog.Warn.Printf("read: ReadAt: %s", err.Error())
		return nil, fuse.ToStatus(err)
	}
	// Truncate ciphertext buffer down to actually read bytes
	ciphertext = ciphertext[0:n]

	firstBlockNo := blocks[0].BlockNo
	tlog.Debug.Printf("ReadAt offset=%d bytes (%d blocks), want=%d, got=%d", alignedOffset, firstBlockNo, alignedLength, n)

	// Decrypt it
	plaintext, err := f.contentEnc.DecryptBlocks(ciphertext, firstBlockNo, f.header.ID)
	if err != nil {
		curruptBlockNo := firstBlockNo + f.contentEnc.PlainOffToBlockNo(uint64(len(plaintext)))
		tlog.Warn.Printf("ino%d: doRead: corrupt block #%d: %v", f.ino, curruptBlockNo, err)
		return nil, fuse.EIO
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

	return out, fuse.OK
}

// Read - FUSE call
func (f *file) Read(buf []byte, off int64) (resultData fuse.ReadResult, code fuse.Status) {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	tlog.Debug.Printf("ino%d: FUSE Read: offset=%d length=%d", f.ino, len(buf), off)

	if f.writeOnly {
		tlog.Warn.Printf("ino%d: Tried to read from write-only file", f.ino)
		return nil, fuse.EBADF
	}

	out, status := f.doRead(uint64(off), uint64(len(buf)))

	if status == fuse.EIO {
		tlog.Warn.Printf("ino%d: Read: returning EIO, offset=%d, length=%d", f.ino, len(buf), off)
	}
	if status != fuse.OK {
		return nil, status
	}

	tlog.Debug.Printf("ino%d: Read: status %v, returning %d bytes", f.ino, status, len(out))
	return fuse.ReadResultData(out), status
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
func (f *file) doWrite(data []byte, off int64) (uint32, fuse.Status) {

	// Read header from disk, create a new one if the file is empty
	if f.header == nil {
		err := f.readHeader()
		if err == io.EOF {
			err = f.createHeader()

		}
		if err != nil {
			return 0, fuse.ToStatus(err)
		}
	}

	var written uint32
	status := fuse.OK
	dataBuf := bytes.NewBuffer(data)
	blocks := f.contentEnc.ExplodePlainRange(uint64(off), uint64(len(data)))
	for _, b := range blocks {

		blockData := dataBuf.Next(int(b.Length))

		// Incomplete block -> Read-Modify-Write
		if b.IsPartial() {
			// Read
			o := b.BlockPlainOff()
			var oldData []byte
			oldData, status = f.doRead(o, f.contentEnc.PlainBS())
			if status != fuse.OK {
				tlog.Warn.Printf("ino%d fh%d: RMW read failed: %s", f.ino, f.intFd(), status.String())
				return written, status
			}
			// Modify
			blockData = f.contentEnc.MergeBlocks(oldData, blockData, int(b.Skip))
			tlog.Debug.Printf("len(oldData)=%d len(blockData)=%d", len(oldData), len(blockData))
		}

		// Encrypt
		blockOffset := b.BlockCipherOff()
		blockData = f.contentEnc.EncryptBlock(blockData, b.BlockNo, f.header.ID)
		tlog.Debug.Printf("ino%d: Writing %d bytes to block #%d",
			f.ino, uint64(len(blockData))-f.contentEnc.BlockOverhead(), b.BlockNo)

		// Prevent partially written (=corrupt) blocks by preallocating the space beforehand
		err := syscallcompat.EnospcPrealloc(int(f.fd.Fd()), int64(blockOffset), int64(len(blockData)))
		if err != nil {
			tlog.Warn.Printf("ino%d fh%d: doWrite: prealloc failed: %s", f.ino, f.intFd(), err.Error())
			status = fuse.ToStatus(err)
			break
		}

		// Write
		_, err = f.fd.WriteAt(blockData, int64(blockOffset))

		if err != nil {
			tlog.Warn.Printf("doWrite: Write failed: %s", err.Error())
			status = fuse.ToStatus(err)
			break
		}
		written += uint32(b.Length)
	}
	return written, status
}

// isConsecutiveWrite returns true if the current write
// directly (in time and space) follows the last write.
// This is an optimisation for streaming writes on NFS where a
// Stat() call is very expensive.
// The caller must "wlock.lock(f.ino)" otherwise this check would be racy.
func (f *file) isConsecutiveWrite(off int64) bool {
	opCount := atomic.LoadUint64(&wlock.opCount)
	return opCount == f.lastOpCount+1 && off == f.lastWrittenOffset+1
}

// Write - FUSE call
//
// If the write creates a hole, pads the file to the next block boundary.
func (f *file) Write(data []byte, off int64) (uint32, fuse.Status) {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	if f.released {
		// The file descriptor has been closed concurrently, which also means
		// the wlock has been freed. Exit here so we don't crash trying to access
		// it.
		tlog.Warn.Printf("ino%d fh%d: Write on released file", f.ino, f.intFd())
		return 0, fuse.EBADF
	}
	wlock.lock(f.ino)
	defer wlock.unlock(f.ino)
	tlog.Debug.Printf("ino%d: FUSE Write: offset=%d length=%d", f.ino, off, len(data))
	// If the write creates a file hole, we have to zero-pad the last block.
	// But if the write directly follows an earlier write, it cannot create a
	// hole, and we can save one Stat() call.
	if !f.isConsecutiveWrite(off) {
		status := f.writePadHole(off)
		if !status.Ok() {
			return 0, status
		}
	}
	n, status := f.doWrite(data, off)
	if status.Ok() {
		f.lastOpCount = atomic.LoadUint64(&wlock.opCount)
		f.lastWrittenOffset = off + int64(len(data)) - 1
	}
	return n, status
}

// Release - FUSE call, close file
func (f *file) Release() {
	f.fdLock.Lock()
	if f.released {
		log.Panicf("ino%d fh%d: double release", f.ino, f.intFd())
	}
	f.fd.Close()
	f.released = true
	f.fdLock.Unlock()

	wlock.unregister(f.ino)
}

// Flush - FUSE call
func (f *file) Flush() fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	// Since Flush() may be called for each dup'd fd, we don't
	// want to really close the file, we just want to flush. This
	// is achieved by closing a dup'd fd.
	newFd, err := syscall.Dup(int(f.fd.Fd()))

	if err != nil {
		return fuse.ToStatus(err)
	}
	err = syscall.Close(newFd)
	return fuse.ToStatus(err)
}

func (f *file) Fsync(flags int) (code fuse.Status) {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	return fuse.ToStatus(syscall.Fsync(int(f.fd.Fd())))
}

func (f *file) Chmod(mode uint32) fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	// os.File.Chmod goes through the "syscallMode" translation function that messes
	// up the suid and sgid bits. So use syscall.Fchmod directly.
	err := syscall.Fchmod(f.intFd(), mode)
	return fuse.ToStatus(err)
}

func (f *file) Chown(uid uint32, gid uint32) fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	return fuse.ToStatus(f.fd.Chown(int(uid), int(gid)))
}

func (f *file) GetAttr(a *fuse.Attr) fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	tlog.Debug.Printf("file.GetAttr()")
	st := syscall.Stat_t{}
	err := syscall.Fstat(int(f.fd.Fd()), &st)
	if err != nil {
		return fuse.ToStatus(err)
	}
	a.FromStat(&st)
	a.Size = f.contentEnc.CipherSizeToPlainSize(a.Size)

	return fuse.OK
}

func (f *file) Utimens(a *time.Time, m *time.Time) fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	return f.loopbackFile.Utimens(a, m)
}
