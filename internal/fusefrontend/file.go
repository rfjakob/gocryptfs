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
	// Device and inode number uniquely identify the backing file
	devIno DevInoStruct
	// Entry in the open file map
	fileTableEntry *openFileEntryT
	// go-fuse nodefs.loopbackFile
	loopbackFile nodefs.File
	// Store where the last byte was written
	lastWrittenOffset int64
	// The opCount is used to judge whether "lastWrittenOffset" is still
	// guaranteed to be correct.
	lastOpCount uint64
	// Parent filesystem
	fs *FS
}

// NewFile returns a new go-fuse File instance.
func NewFile(fd *os.File, writeOnly bool, fs *FS) (nodefs.File, fuse.Status) {
	var st syscall.Stat_t
	err := syscall.Fstat(int(fd.Fd()), &st)
	if err != nil {
		tlog.Warn.Printf("NewFile: Fstat on fd %d failed: %v\n", fd.Fd(), err)
		return nil, fuse.ToStatus(err)
	}
	di := DevInoFromStat(&st)
	t := openFileMap.register(di)

	return &file{
		fd:             fd,
		writeOnly:      writeOnly,
		contentEnc:     fs.contentEnc,
		devIno:         di,
		fileTableEntry: t,
		loopbackFile:   nodefs.NewLoopbackFile(fd),
		fs:             fs,
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

// readFileID loads the file header from disk and extracts the file ID.
// Returns io.EOF if the file is empty.
func (f *file) readFileID() ([]byte, error) {
	buf := make([]byte, contentenc.HeaderLen)
	_, err := f.fd.ReadAt(buf, 0)
	if err != nil {
		return nil, err
	}
	h, err := contentenc.ParseHeader(buf)
	if err != nil {
		return nil, err
	}
	return h.ID, nil
}

// createHeader creates a new random header and writes it to disk.
// Returns the new file ID.
// The caller must hold fileIDLock.Lock().
func (f *file) createHeader() (fileID []byte, err error) {
	h := contentenc.RandomHeader()
	buf := h.Pack()
	// Prevent partially written (=corrupt) header by preallocating the space beforehand
	if !f.fs.args.NoPrealloc {
		err = syscallcompat.EnospcPrealloc(int(f.fd.Fd()), 0, contentenc.HeaderLen)
		if err != nil {
			tlog.Warn.Printf("ino%d: createHeader: prealloc failed: %s\n", f.devIno.ino, err.Error())
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
	// Make sure we have the file ID.
	f.fileTableEntry.IDLock.RLock()
	if f.fileTableEntry.ID == nil {
		f.fileTableEntry.IDLock.RUnlock()
		// Yes, somebody else may take the lock before we can. This will get
		// the header read twice, but causes no harm otherwise.
		f.fileTableEntry.IDLock.Lock()
		tmpID, err := f.readFileID()
		if err == io.EOF {
			f.fileTableEntry.IDLock.Unlock()
			return nil, fuse.OK
		}
		if err != nil {
			f.fileTableEntry.IDLock.Unlock()
			return nil, fuse.ToStatus(err)
		}
		f.fileTableEntry.ID = tmpID
		// Downgrade the lock.
		f.fileTableEntry.IDLock.Unlock()
		// The file ID may change in here. This does no harm because we
		// re-read it after the RLock().
		f.fileTableEntry.IDLock.RLock()
	}
	fileID := f.fileTableEntry.ID
	// Read the backing ciphertext in one go
	blocks := f.contentEnc.ExplodePlainRange(off, length)
	alignedOffset, alignedLength := blocks[0].JointCiphertextRange(blocks)
	skip := blocks[0].Skip
	tlog.Debug.Printf("JointCiphertextRange(%d, %d) -> %d, %d, %d", off, length, alignedOffset, alignedLength, skip)
	ciphertext := make([]byte, int(alignedLength))
	n, err := f.fd.ReadAt(ciphertext, int64(alignedOffset))
	// We don't care if the file ID changes after we have read the data. Drop the lock.
	f.fileTableEntry.IDLock.RUnlock()
	if err != nil && err != io.EOF {
		tlog.Warn.Printf("read: ReadAt: %s", err.Error())
		return nil, fuse.ToStatus(err)
	}
	// Truncate ciphertext buffer down to actually read bytes
	ciphertext = ciphertext[0:n]

	firstBlockNo := blocks[0].BlockNo
	tlog.Debug.Printf("ReadAt offset=%d bytes (%d blocks), want=%d, got=%d", alignedOffset, firstBlockNo, alignedLength, n)

	// Decrypt it
	plaintext, err := f.contentEnc.DecryptBlocks(ciphertext, firstBlockNo, fileID)
	if err != nil {
		curruptBlockNo := firstBlockNo + f.contentEnc.PlainOffToBlockNo(uint64(len(plaintext)))
		tlog.Warn.Printf("ino%d: doRead: corrupt block #%d: %v", f.devIno.ino, curruptBlockNo, err)
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

	tlog.Debug.Printf("ino%d: FUSE Read: offset=%d length=%d", f.devIno.ino, len(buf), off)

	if f.writeOnly {
		tlog.Warn.Printf("ino%d: Tried to read from write-only file", f.devIno.ino)
		return nil, fuse.EBADF
	}

	out, status := f.doRead(uint64(off), uint64(len(buf)))

	if status == fuse.EIO {
		tlog.Warn.Printf("ino%d: Read: returning EIO, offset=%d, length=%d", f.devIno.ino, len(buf), off)
	}
	if status != fuse.OK {
		return nil, status
	}

	tlog.Debug.Printf("ino%d: Read: status %v, returning %d bytes", f.devIno.ino, status, len(out))
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
	f.fileTableEntry.IDLock.RLock()
	if f.fileTableEntry.ID == nil {
		f.fileTableEntry.IDLock.RUnlock()
		// Somebody else may write the header here, but this would do no harm.
		f.fileTableEntry.IDLock.Lock()
		tmpID, err := f.readFileID()
		if err == io.EOF {
			tmpID, err = f.createHeader()
		}
		if err != nil {
			f.fileTableEntry.IDLock.Unlock()
			return 0, fuse.ToStatus(err)
		}
		f.fileTableEntry.ID = tmpID
		f.fileTableEntry.IDLock.Unlock()
		// The file ID may change in here. This does no harm because we
		// re-read it after the RLock().
		f.fileTableEntry.IDLock.RLock()
	}
	fileID := f.fileTableEntry.ID
	defer f.fileTableEntry.IDLock.RUnlock()
	// Handle payload data
	status := fuse.OK
	dataBuf := bytes.NewBuffer(data)
	blocks := f.contentEnc.ExplodePlainRange(uint64(off), uint64(len(data)))
	writeChain := make([][]byte, len(blocks))
	var numOutBytes int
	for i, b := range blocks {
		blockData := dataBuf.Next(int(b.Length))
		// Incomplete block -> Read-Modify-Write
		if b.IsPartial() {
			// Read
			o := b.BlockPlainOff()
			var oldData []byte
			oldData, status = f.doRead(o, f.contentEnc.PlainBS())
			if status != fuse.OK {
				tlog.Warn.Printf("ino%d fh%d: RMW read failed: %s", f.devIno.ino, f.intFd(), status.String())
				return 0, status
			}
			// Modify
			blockData = f.contentEnc.MergeBlocks(oldData, blockData, int(b.Skip))
			tlog.Debug.Printf("len(oldData)=%d len(blockData)=%d", len(oldData), len(blockData))
		}
		// Encrypt
		blockData = f.contentEnc.EncryptBlock(blockData, b.BlockNo, fileID)
		tlog.Debug.Printf("ino%d: Writing %d bytes to block #%d",
			f.devIno.ino, uint64(len(blockData))-f.contentEnc.BlockOverhead(), b.BlockNo)
		// Store output data in the writeChain
		writeChain[i] = blockData
		numOutBytes += len(blockData)
	}
	// Concatenenate all elements in the writeChain into one contiguous buffer
	tmp := make([]byte, numOutBytes)
	writeBuf := bytes.NewBuffer(tmp[:0])
	for _, w := range writeChain {
		writeBuf.Write(w)
	}
	// Preallocate so we cannot run out of space in the middle of the write.
	// This prevents partially written (=corrupt) blocks.
	var err error
	cOff := blocks[0].BlockCipherOff()
	if !f.fs.args.NoPrealloc {
		err = syscallcompat.EnospcPrealloc(int(f.fd.Fd()), int64(cOff), int64(writeBuf.Len()))
		if err != nil {
			tlog.Warn.Printf("ino%d fh%d: doWrite: prealloc failed: %s", f.devIno.ino, f.intFd(), err.Error())
			return 0, fuse.ToStatus(err)
		}
	}
	// Write
	_, err = f.fd.WriteAt(writeBuf.Bytes(), int64(cOff))
	if err != nil {
		tlog.Warn.Printf("doWrite: Write failed: %s", err.Error())
		return 0, fuse.ToStatus(err)
	}
	return uint32(len(data)), fuse.OK
}

// isConsecutiveWrite returns true if the current write
// directly (in time and space) follows the last write.
// This is an optimisation for streaming writes on NFS where a
// Stat() call is very expensive.
// The caller must "wlock.lock(f.devIno.ino)" otherwise this check would be racy.
func (f *file) isConsecutiveWrite(off int64) bool {
	opCount := atomic.LoadUint64(&openFileMap.opCount)
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
		tlog.Warn.Printf("ino%d fh%d: Write on released file", f.devIno.ino, f.intFd())
		return 0, fuse.EBADF
	}
	f.fileTableEntry.writeLock.Lock()
	defer f.fileTableEntry.writeLock.Unlock()
	tlog.Debug.Printf("ino%d: FUSE Write: offset=%d length=%d", f.devIno.ino, off, len(data))
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
		f.lastOpCount = atomic.LoadUint64(&openFileMap.opCount)
		f.lastWrittenOffset = off + int64(len(data)) - 1
	}
	return n, status
}

// Release - FUSE call, close file
func (f *file) Release() {
	f.fdLock.Lock()
	if f.released {
		log.Panicf("ino%d fh%d: double release", f.devIno.ino, f.intFd())
	}
	f.fd.Close()
	f.released = true
	f.fdLock.Unlock()

	openFileMap.unregister(f.devIno)
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
