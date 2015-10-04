package pathfs_frontend

import (
	"io"
	"bytes"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/rfjakob/gocryptfs/cryptfs"
)

// File - based on loopbackFile in go-fuse/fuse/nodefs/files.go
type file struct {
	fd *os.File

	// os.File is not threadsafe. Although fd themselves are
	// constant during the lifetime of an open file, the OS may
	// reuse the fd number after it is closed. When open races
	// with another close, they may lead to confusion as which
	// file gets written in the end.
	lock sync.Mutex

	// Was the file opened O_WRONLY?
	writeOnly bool

	// Parent CryptFS
	cfs *cryptfs.CryptFS

	// Inode number
	ino uint64
}

func NewFile(fd *os.File, writeOnly bool, cfs *cryptfs.CryptFS) nodefs.File {
	var st syscall.Stat_t
	syscall.Fstat(int(fd.Fd()), &st)

	return &file{
		fd: fd,
		writeOnly: writeOnly,
		cfs: cfs,
		ino: st.Ino,
	}
}

func (f *file) InnerFile() nodefs.File {
	return nil
}

func (f *file) SetInode(n *nodefs.Inode) {
}

func (f *file) String() string {
	return fmt.Sprintf("cryptFile(%s)", f.fd.Name())
}

// doRead - returns "length" plaintext bytes from plaintext offset "off".
// Arguments "length" and "off" do not have to be aligned.
//
// doRead reads the corresponding ciphertext blocks from disk, decryptfs them and
// returns the requested part of the plaintext.
//
// Called by Read() and by Write() and Truncate() for RMW
func (f *file) doRead(off uint64, length uint64) ([]byte, fuse.Status) {

	// Read the backing ciphertext in one go
	alignedOffset, alignedLength, skip := f.cfs.CiphertextRange(off, length)
	cryptfs.Debug.Printf("CiphertextRange(%d, %d) -> %d, %d, %d\n", off, length, alignedOffset, alignedLength, skip)
	ciphertext := make([]byte, int(alignedLength))
	f.lock.Lock()
	n, err := f.fd.ReadAt(ciphertext, int64(alignedOffset))
	f.lock.Unlock()
	if err != nil && err != io.EOF {
		cryptfs.Warn.Printf("read: ReadAt: %s\n", err.Error())
		return nil, fuse.ToStatus(err)
	}
	// Truncate ciphertext buffer down to actually read bytes
	ciphertext = ciphertext[0:n]
	{
		blockNo := alignedOffset / f.cfs.CipherBS()
		cryptfs.Debug.Printf("ReadAt offset=%d bytes (%d blocks), want=%d, got=%d\n", alignedOffset, blockNo, alignedLength, n)
	}

	// Decrypt it
	plaintext, err := f.cfs.DecryptBlocks(ciphertext)
	if err != nil {
		blockNo := (alignedOffset + uint64(len(plaintext))) / f.cfs.PlainBS()
		cipherOff := blockNo * f.cfs.CipherBS()
		plainOff := blockNo * f.cfs.PlainBS()
		cryptfs.Warn.Printf("ino%d: doRead: corrupt block #%d (plainOff=%d/%d, cipherOff=%d/%d)\n",
			f.ino, blockNo, plainOff, f.cfs.PlainBS(), cipherOff, f.cfs.CipherBS())
		return nil, fuse.EIO
	}

	// Crop down to the relevant part
	var out []byte
	lenHave := len(plaintext)
	lenWant := skip + int(length)
	if lenHave > lenWant {
		out = plaintext[skip:skip +  int(length)]
	} else if lenHave > skip {
		out = plaintext[skip:lenHave]
	} else {
		// Out stays empty, file was smaller than the requested offset
	}

	return out, fuse.OK
}

// Read - FUSE call
func (f *file) Read(buf []byte, off int64) (resultData fuse.ReadResult, code fuse.Status) {
	cryptfs.Debug.Printf("ino%d: FUSE Read: offset=%d length=%d\n", f.ino, len(buf), off)

	if f.writeOnly {
		cryptfs.Warn.Printf("ino%d: Tried to read from write-only file\n", f.ino)
		return nil, fuse.EBADF
	}

	out, status := f.doRead(uint64(off), uint64(len(buf)))

	if status == fuse.EIO {
		cryptfs.Warn.Printf("ino%d: Read failed with EIO, offset=%d, length=%d\n", f.ino, len(buf), off)
	}
	if status != fuse.OK {
		return nil, status
	}

	cryptfs.Debug.Printf("ino%d: Read: status %v, returning %d bytes\n", f.ino, status, len(out))
	return fuse.ReadResultData(out), status
}

// Do the actual write
func (f *file) doWrite(data []byte, off int64) (uint32, fuse.Status) {
	var written uint32
	status := fuse.OK
	dataBuf := bytes.NewBuffer(data)
	blocks := f.cfs.SplitRange(uint64(off), uint64(len(data)))
	for _, b := range(blocks) {

		blockData := dataBuf.Next(int(b.Length))

		// Incomplete block -> Read-Modify-Write
		if b.IsPartial() {
			// Read
			o, _ := b.PlaintextRange()
			oldData, status := f.doRead(o, f.cfs.PlainBS())
			if status != fuse.OK {
				cryptfs.Warn.Printf("RMW read failed: %s\n", status.String())
				return written, status
			}
			// Modify
			blockData = f.cfs.MergeBlocks(oldData, blockData, int(b.Offset))
			cryptfs.Debug.Printf("len(oldData)=%d len(blockData)=%d\n", len(oldData), len(blockData))
		}

		// Write
		blockOffset, _ := b.CiphertextRange()
		blockData = f.cfs.EncryptBlock(blockData)
		cryptfs.Debug.Printf("ino%d: Writing %d bytes to block #%d, md5=%s\n", f.ino, len(blockData), b.BlockNo, cryptfs.Debug.Md5sum(blockData))
		if len(blockData) != int(f.cfs.CipherBS()) {
			cryptfs.Debug.Printf("ino%d: Writing partial block #%d (%d bytes)\n", f.ino, b.BlockNo, len(blockData))
		}
		f.lock.Lock()
		_, err := f.fd.WriteAt(blockData, int64(blockOffset))
		f.lock.Unlock()

		if err != nil {
			cryptfs.Warn.Printf("Write failed: %s\n", err.Error())
			status = fuse.ToStatus(err)
			break
		}
		written += uint32(b.Length)
	}
	return written, status
}

// Write - FUSE call
func (f *file) Write(data []byte, off int64) (uint32, fuse.Status) {
	cryptfs.Debug.Printf("ino%d: FUSE Write %s: offset=%d length=%d\n", f.ino, off, len(data))
	f.conditionalZeroPad(off)
	return f.doWrite(data, off)
}

// Release - FUSE call, forget file
func (f *file) Release() {
	f.lock.Lock()
	f.fd.Close()
	f.lock.Unlock()
}

// Flush - FUSE call
func (f *file) Flush() fuse.Status {
	f.lock.Lock()

	// Since Flush() may be called for each dup'd fd, we don't
	// want to really close the file, we just want to flush. This
	// is achieved by closing a dup'd fd.
	newFd, err := syscall.Dup(int(f.fd.Fd()))
	f.lock.Unlock()

	if err != nil {
		return fuse.ToStatus(err)
	}
	err = syscall.Close(newFd)
	return fuse.ToStatus(err)
}

func (f *file) Fsync(flags int) (code fuse.Status) {
	f.lock.Lock()
	r := fuse.ToStatus(syscall.Fsync(int(f.fd.Fd())))
	f.lock.Unlock()

	return r
}

func (f *file) Truncate(newSize uint64) fuse.Status {

	// Common case: Truncate to zero
	if newSize == 0 {
		f.lock.Lock()
		err := syscall.Ftruncate(int(f.fd.Fd()), 0)
		f.lock.Unlock()
		return fuse.ToStatus(err)
	}

	// We need the old file size to determine if we are growing or shrinking
	// the file
	fi, err := f.fd.Stat()
	if err != nil {
		cryptfs.Warn.Printf("Truncate: fstat failed: %v\n", err)
		return fuse.ToStatus(err)
	}
	oldSize := f.cfs.PlainSize(uint64(fi.Size()))
	{
		oldB := (oldSize + f.cfs.PlainBS() - 1) / f.cfs.PlainBS()
		newB := (newSize + f.cfs.PlainBS() - 1) / f.cfs.PlainBS()
		cryptfs.Debug.Printf("ino%d: truncate from %d to %d blocks (%d to %d bytes)\n", f.ino, oldB, newB, oldSize, newSize)
	}
	// Grow file by appending zeros
	if newSize > oldSize {
		remaining := newSize - oldSize
		offset := oldSize
		var zeros []byte
		// Append a maximum of 1MB in each iteration
		if remaining > 1048576 {
			zeros = make([]byte, 1048576)
		} else {
			zeros = make([]byte, remaining)
		}
		for remaining >= uint64(len(zeros)) {
			written, status := f.Write(zeros, int64(offset))
			if status != fuse.OK {
				return status
			}
			remaining -= uint64(written)
			offset += uint64(written)
			cryptfs.Debug.Printf("Truncate: written=%d remaining=%d offset=%d\n",
				written, remaining, offset)
		}
		if remaining > 0 {
			_, status := f.Write(zeros[0:remaining], int64(offset))
			return status
		}
		return fuse.OK
	}
	// else:
	// Shrink file by truncating
	newBlockLen := int(newSize % f.cfs.PlainBS())
	// New file size is aligned to block size - just truncate
	if newBlockLen == 0 {
		cSize := int64(f.cfs.CipherSize(newSize))
		f.lock.Lock()
		err := syscall.Ftruncate(int(f.fd.Fd()), cSize)
		f.lock.Unlock()
		return fuse.ToStatus(err)
	}
	// New file size is not aligned - need to do RMW on the last block
	cryptfs.Debug.Printf("Truncate: Shrink RMW\n")
	var blockOffset, blockLen uint64
	{
		// Get the block the last byte belongs to.
		// This is, by definition, the last block.
		blockList := f.cfs.SplitRange(newSize - 1, 1)
		lastBlock := blockList[0]
		blockOffset, blockLen = lastBlock.PlaintextRange()
	}
	blockData, status := f.doRead(blockOffset, blockLen)
	if status != fuse.OK {
		cryptfs.Warn.Printf("Truncate: doRead failed: %v\n", err)
		return status
	}
	if len(blockData) < newBlockLen {
		cryptfs.Warn.Printf("Truncate: file has shrunk under our feet\n")
		return fuse.OK
	}
	// Truncate the file down to the next block
	{
		nextBlockSz := int64(f.cfs.CipherSize(newSize - uint64(newBlockLen)))
		f.lock.Lock()
		err = syscall.Ftruncate(int(f.fd.Fd()), nextBlockSz)
		f.lock.Unlock()
		if err != nil {
			cryptfs.Warn.Printf("Truncate: Intermediate Ftruncate failed: %v\n", err)
			return fuse.ToStatus(err)
		}
	}
	// Append truncated last block
	_, status = f.Write(blockData[0:newBlockLen], int64(blockOffset))
	return status
}

func (f *file) Chmod(mode uint32) fuse.Status {
	f.lock.Lock()
	r := fuse.ToStatus(f.fd.Chmod(os.FileMode(mode)))
	f.lock.Unlock()

	return r
}

func (f *file) Chown(uid uint32, gid uint32) fuse.Status {
	f.lock.Lock()
	r := fuse.ToStatus(f.fd.Chown(int(uid), int(gid)))
	f.lock.Unlock()

	return r
}

func (f *file) GetAttr(a *fuse.Attr) fuse.Status {
	cryptfs.Debug.Printf("file.GetAttr()\n")
	st := syscall.Stat_t{}
	f.lock.Lock()
	err := syscall.Fstat(int(f.fd.Fd()), &st)
	f.lock.Unlock()
	if err != nil {
		return fuse.ToStatus(err)
	}
	a.FromStat(&st)
	a.Size = f.cfs.PlainSize(a.Size)

	return fuse.OK
}

func (f *file) Allocate(off uint64, sz uint64, mode uint32) fuse.Status {
	f.lock.Lock()
	err := syscall.Fallocate(int(f.fd.Fd()), mode, int64(off), int64(sz))
	f.lock.Unlock()
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fuse.OK
}

const _UTIME_NOW = ((1 << 30) - 1)
const _UTIME_OMIT = ((1 << 30) - 2)

func (f *file) Utimens(a *time.Time, m *time.Time) fuse.Status {
	tv := make([]syscall.Timeval, 2)
	if a == nil {
		tv[0].Usec = _UTIME_OMIT
	} else {
		n := a.UnixNano()
		tv[0] = syscall.NsecToTimeval(n)
	}

	if m == nil {
		tv[1].Usec = _UTIME_OMIT
	} else {
		n := a.UnixNano()
		tv[1] = syscall.NsecToTimeval(n)
	}

	f.lock.Lock()
	err := syscall.Futimes(int(f.fd.Fd()), tv)
	f.lock.Unlock()
	return fuse.ToStatus(err)
}
