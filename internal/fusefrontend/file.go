package fusefrontend

// FUSE operations on file handles

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/openfiletable"
	"github.com/rfjakob/gocryptfs/internal/serialize_reads"
	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

var _ nodefs.File = &file{} // Verify that interface is implemented.

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
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// Device and inode number uniquely identify the backing file
	qIno openfiletable.QIno
	// Entry in the open file table
	fileTableEntry *openfiletable.Entry
	// go-fuse nodefs.loopbackFile
	loopbackFile nodefs.File
	// Store where the last byte was written
	lastWrittenOffset int64
	// The opCount is used to judge whether "lastWrittenOffset" is still
	// guaranteed to be correct.
	lastOpCount uint64
	// Parent filesystem
	fs *FS
	// We embed a nodefs.NewDefaultFile() that returns ENOSYS for every operation we
	// have not implemented. This prevents build breakage when the go-fuse library
	// adds new methods to the nodefs.File interface.
	nodefs.File
}

// NewFile returns a new go-fuse File instance.
func NewFile(fd *os.File, fs *FS) (nodefs.File, fuse.Status) {
	var st syscall.Stat_t
	err := syscall.Fstat(int(fd.Fd()), &st)
	if err != nil {
		tlog.Warn.Printf("NewFile: Fstat on fd %d failed: %v\n", fd.Fd(), err)
		return nil, fuse.ToStatus(err)
	}
	qi := openfiletable.QInoFromStat(&st)
	e := openfiletable.Register(qi)

	return &file{
		fd:             fd,
		contentEnc:     fs.contentEnc,
		qIno:           qi,
		fileTableEntry: e,
		loopbackFile:   nodefs.NewLoopbackFile(fd),
		fs:             fs,
		File:           nodefs.NewDefaultFile(),
	}, fuse.OK
}

// intFd - return the backing file descriptor as an integer. Used for debug
// messages.
func (f *file) intFd() int {
	return int(f.fd.Fd())
}

// readFileID loads the file header from disk and extracts the file ID.
// Returns io.EOF if the file is empty.
func (f *file) readFileID() ([]byte, error) {
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
			f.fs.reportMitigatedCorruption(fmt.Sprint(f.qIno.Ino))
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
func (f *file) createHeader() (fileID []byte, err error) {
	h := contentenc.RandomHeader()
	buf := h.Pack()
	// Prevent partially written (=corrupt) header by preallocating the space beforehand
	if !f.fs.args.NoPrealloc {
		err = syscallcompat.EnospcPrealloc(int(f.fd.Fd()), 0, contentenc.HeaderLen)
		if err != nil {
			tlog.Warn.Printf("ino%d: createHeader: prealloc failed: %s\n", f.qIno.Ino, err.Error())
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
// by Write() and Truncate() for Read-Modify-Write
func (f *file) doRead(dst []byte, off uint64, length uint64) ([]byte, fuse.Status) {
	// Make sure we have the file ID.
	f.fileTableEntry.HeaderLock.RLock()
	if f.fileTableEntry.ID == nil {
		f.fileTableEntry.HeaderLock.RUnlock()
		// Yes, somebody else may take the lock before we can. This will get
		// the header read twice, but causes no harm otherwise.
		f.fileTableEntry.HeaderLock.Lock()
		tmpID, err := f.readFileID()
		if err == io.EOF {
			f.fileTableEntry.HeaderLock.Unlock()
			return nil, fuse.OK
		}
		if err != nil {
			f.fileTableEntry.HeaderLock.Unlock()
			tlog.Warn.Printf("doRead %d: corrupt header: %v", f.qIno.Ino, err)
			return nil, fuse.EIO
		}
		f.fileTableEntry.ID = tmpID
		// Downgrade the lock.
		f.fileTableEntry.HeaderLock.Unlock()
		// The file ID may change in here. This does no harm because we
		// re-read it after the RLock().
		f.fileTableEntry.HeaderLock.RLock()
	}
	fileID := f.fileTableEntry.ID
	// Read the backing ciphertext in one go
	blocks := f.contentEnc.ExplodePlainRange(off, length)
	alignedOffset, alignedLength := blocks[0].JointCiphertextRange(blocks)
	skip := blocks[0].Skip
	tlog.Debug.Printf("doRead: off=%d len=%d -> off=%d len=%d skip=%d\n",
		off, length, alignedOffset, alignedLength, skip)

	ciphertext := f.fs.contentEnc.CReqPool.Get()
	ciphertext = ciphertext[:int(alignedLength)]
	n, err := f.fd.ReadAt(ciphertext, int64(alignedOffset))
	// We don't care if the file ID changes after we have read the data. Drop the lock.
	f.fileTableEntry.HeaderLock.RUnlock()
	if err != nil && err != io.EOF {
		tlog.Warn.Printf("read: ReadAt: %s", err.Error())
		return nil, fuse.ToStatus(err)
	}
	// The ReadAt came back empty. We can skip all the decryption and return early.
	if n == 0 {
		f.fs.contentEnc.CReqPool.Put(ciphertext)
		return dst, fuse.OK
	}
	// Truncate ciphertext buffer down to actually read bytes
	ciphertext = ciphertext[0:n]

	firstBlockNo := blocks[0].BlockNo
	tlog.Debug.Printf("ReadAt offset=%d bytes (%d blocks), want=%d, got=%d", alignedOffset, firstBlockNo, alignedLength, n)

	// Decrypt it
	plaintext, err := f.contentEnc.DecryptBlocks(ciphertext, firstBlockNo, fileID)
	f.fs.contentEnc.CReqPool.Put(ciphertext)
	if err != nil {
		if f.fs.args.ForceDecode && err == stupidgcm.ErrAuth {
			// We do not have the information which block was corrupt here anymore,
			// but DecryptBlocks() has already logged it anyway.
			tlog.Warn.Printf("doRead %d: off=%d len=%d: returning corrupt data due to forcedecode",
				f.qIno.Ino, off, length)
		} else {
			curruptBlockNo := firstBlockNo + f.contentEnc.PlainOffToBlockNo(uint64(len(plaintext)))
			tlog.Warn.Printf("doRead %d: corrupt block #%d: %v", f.qIno.Ino, curruptBlockNo, err)
			return nil, fuse.EIO
		}
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
	f.fs.contentEnc.PReqPool.Put(plaintext)

	return out, fuse.OK
}

// Read - FUSE call
func (f *file) Read(buf []byte, off int64) (resultData fuse.ReadResult, code fuse.Status) {
	if len(buf) > fuse.MAX_KERNEL_WRITE {
		// This would crash us due to our fixed-size buffer pool
		tlog.Warn.Printf("Read: rejecting oversized request with EMSGSIZE, len=%d", len(buf))
		return nil, fuse.Status(syscall.EMSGSIZE)
	}
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	tlog.Debug.Printf("ino%d: FUSE Read: offset=%d length=%d", f.qIno.Ino, len(buf), off)
	if f.fs.args.SerializeReads {
		serialize_reads.Wait(off, len(buf))
	}
	out, status := f.doRead(buf[:0], uint64(off), uint64(len(buf)))
	if f.fs.args.SerializeReads {
		serialize_reads.Done()
	}
	if status != fuse.OK {
		return nil, status
	}
	tlog.Debug.Printf("ino%d: Read: status %v, returning %d bytes", f.qIno.Ino, status, len(out))
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
	f.fileTableEntry.HeaderLock.RLock()
	if f.fileTableEntry.ID == nil {
		f.fileTableEntry.HeaderLock.RUnlock()
		// Somebody else may write the header here, but this would do no harm.
		f.fileTableEntry.HeaderLock.Lock()
		tmpID, err := f.readFileID()
		if err == io.EOF {
			tmpID, err = f.createHeader()
		}
		if err != nil {
			f.fileTableEntry.HeaderLock.Unlock()
			return 0, fuse.ToStatus(err)
		}
		f.fileTableEntry.ID = tmpID
		f.fileTableEntry.HeaderLock.Unlock()
		// The file ID may change in here. This does no harm because we
		// re-read it after the RLock().
		f.fileTableEntry.HeaderLock.RLock()
	}
	defer f.fileTableEntry.HeaderLock.RUnlock()
	// Handle payload data
	dataBuf := bytes.NewBuffer(data)
	blocks := f.contentEnc.ExplodePlainRange(uint64(off), uint64(len(data)))
	toEncrypt := make([][]byte, len(blocks))
	for i, b := range blocks {
		blockData := dataBuf.Next(int(b.Length))
		// Incomplete block -> Read-Modify-Write
		if b.IsPartial() {
			// Read
			oldData, status := f.doRead(nil, b.BlockPlainOff(), f.contentEnc.PlainBS())
			if status != fuse.OK {
				tlog.Warn.Printf("ino%d fh%d: RMW read failed: %s", f.qIno.Ino, f.intFd(), status.String())
				return 0, status
			}
			// Modify
			blockData = f.contentEnc.MergeBlocks(oldData, blockData, int(b.Skip))
			tlog.Debug.Printf("len(oldData)=%d len(blockData)=%d", len(oldData), len(blockData))
		}
		tlog.Debug.Printf("ino%d: Writing %d bytes to block #%d",
			f.qIno.Ino, uint64(len(blockData))-f.contentEnc.BlockOverhead(), b.BlockNo)
		// Write into the to-encrypt list
		toEncrypt[i] = blockData
	}
	// Encrypt all blocks
	ciphertext := f.contentEnc.EncryptBlocks(toEncrypt, blocks[0].BlockNo, f.fileTableEntry.ID)
	// Preallocate so we cannot run out of space in the middle of the write.
	// This prevents partially written (=corrupt) blocks.
	var err error
	cOff := int64(blocks[0].BlockCipherOff())
	if !f.fs.args.NoPrealloc {
		err = syscallcompat.EnospcPrealloc(int(f.fd.Fd()), cOff, int64(len(ciphertext)))
		if err != nil {
			tlog.Warn.Printf("ino%d fh%d: doWrite: prealloc failed: %s", f.qIno.Ino, f.intFd(), err.Error())
			return 0, fuse.ToStatus(err)
		}
	}
	// Write
	_, err = f.fd.WriteAt(ciphertext, cOff)
	// Return memory to CReqPool
	f.fs.contentEnc.CReqPool.Put(ciphertext)
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
	opCount := openfiletable.WriteOpCount()
	return opCount == f.lastOpCount+1 && off == f.lastWrittenOffset+1
}

// Write - FUSE call
//
// If the write creates a hole, pads the file to the next block boundary.
func (f *file) Write(data []byte, off int64) (uint32, fuse.Status) {
	if len(data) > fuse.MAX_KERNEL_WRITE {
		// This would crash us due to our fixed-size buffer pool
		tlog.Warn.Printf("Write: rejecting oversized request with EMSGSIZE, len=%d", len(data))
		return 0, fuse.Status(syscall.EMSGSIZE)
	}
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	if f.released {
		// The file descriptor has been closed concurrently, which also means
		// the wlock has been freed. Exit here so we don't crash trying to access
		// it.
		tlog.Warn.Printf("ino%d fh%d: Write on released file", f.qIno.Ino, f.intFd())
		return 0, fuse.EBADF
	}
	f.fileTableEntry.ContentLock.Lock()
	defer f.fileTableEntry.ContentLock.Unlock()
	tlog.Debug.Printf("ino%d: FUSE Write: offset=%d length=%d", f.qIno.Ino, off, len(data))
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
		f.lastOpCount = openfiletable.WriteOpCount()
		f.lastWrittenOffset = off + int64(len(data)) - 1
	}
	return n, status
}

// Release - FUSE call, close file
func (f *file) Release() {
	f.fdLock.Lock()
	if f.released {
		log.Panicf("ino%d fh%d: double release", f.qIno.Ino, f.intFd())
	}
	f.fd.Close()
	f.released = true
	f.fdLock.Unlock()

	openfiletable.Unregister(f.qIno)
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
	if f.fs.args.ForceOwner != nil {
		a.Owner = *f.fs.args.ForceOwner
	}

	return fuse.OK
}

func (f *file) Utimens(a *time.Time, m *time.Time) fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	return f.loopbackFile.Utimens(a, m)
}
