package pathfs_frontend

// FUSE operations on file handles

import (
	"bytes"
	"fmt"
	"io"
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
	fdLock sync.Mutex

	// Was the file opened O_WRONLY?
	writeOnly bool

	// Parent CryptFS
	cfs *cryptfs.CryptFS

	// Inode number
	ino uint64

	// File header
	header *cryptfs.FileHeader
}

func NewFile(fd *os.File, writeOnly bool, cfs *cryptfs.CryptFS) nodefs.File {
	var st syscall.Stat_t
	syscall.Fstat(int(fd.Fd()), &st)

	return &file{
		fd:        fd,
		writeOnly: writeOnly,
		cfs:       cfs,
		ino:       st.Ino,
	}
}

func (f *file) InnerFile() nodefs.File {
	return nil
}

func (f *file) SetInode(n *nodefs.Inode) {
}

// Ensure that all modifications to the file contents are serialized and no
// reads happen concurrently.
//
// This prevents several races:
// * getFileId vs Truncate
// * zeroPad vs Read
// * RMW vs Write
func (f *file) wlock() {
}
func (f *file) rlock() {
}
func (f *file) unlock() {
}

// readHeader - load the file header from disk
//
// Returns io.EOF if the file is empty
func (f *file) readHeader() error {
	buf := make([]byte, cryptfs.HEADER_LEN)
	_, err := f.fd.ReadAt(buf, 0)
	if err != nil {
		return err
	}
	h, err := cryptfs.ParseHeader(buf)
	if err != nil {
		return err
	}
	f.header = h

	return nil
}

// createHeader - create a new random header and write it to disk
func (f *file) createHeader() error {
	h := cryptfs.RandomHeader()
	buf := h.Pack()

	// Prevent partially written (=corrupt) header by preallocating the space beforehand
	f.fdLock.Lock()
	defer f.fdLock.Unlock()
	err := fallocateRetry(int(f.fd.Fd()), FALLOC_FL_KEEP_SIZE, 0, cryptfs.HEADER_LEN)
	if err != nil {
		cryptfs.Warn.Printf("createHeader: fallocateRetry failed: %s\n", err.Error())
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
	blocks := f.cfs.ExplodePlainRange(off, length)
	alignedOffset, alignedLength := blocks[0].JointCiphertextRange(blocks)
	skip := blocks[0].Skip
	cryptfs.Debug.Printf("JointCiphertextRange(%d, %d) -> %d, %d, %d\n", off, length, alignedOffset, alignedLength, skip)
	ciphertext := make([]byte, int(alignedLength))
	f.fdLock.Lock()
	n, err := f.fd.ReadAt(ciphertext, int64(alignedOffset))
	f.fdLock.Unlock()
	if err != nil && err != io.EOF {
		cryptfs.Warn.Printf("read: ReadAt: %s\n", err.Error())
		return nil, fuse.ToStatus(err)
	}
	// Truncate ciphertext buffer down to actually read bytes
	ciphertext = ciphertext[0:n]

	firstBlockNo := blocks[0].BlockNo
	cryptfs.Debug.Printf("ReadAt offset=%d bytes (%d blocks), want=%d, got=%d\n", alignedOffset, firstBlockNo, alignedLength, n)

	// Decrypt it
	plaintext, err := f.cfs.DecryptBlocks(ciphertext, firstBlockNo, f.header.Id)
	if err != nil {
		curruptBlockNo := firstBlockNo + f.cfs.PlainOffToBlockNo(uint64(len(plaintext)))
		cipherOff := f.cfs.BlockNoToCipherOff(curruptBlockNo)
		plainOff := f.cfs.BlockNoToPlainOff(curruptBlockNo)
		cryptfs.Warn.Printf("ino%d: doRead: corrupt block #%d (plainOff=%d, cipherOff=%d)\n",
			f.ino, curruptBlockNo, plainOff, cipherOff)
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

// fallocateRetry - syscall.Fallocate() with retry for EINTR.
func fallocateRetry(fd int, mode uint32, off int64, len int64) (err error) {
	for {
		err = syscall.Fallocate(fd, mode, off, len)
		if err == syscall.EINTR {
			continue
		}
		return err
	}
}

const FALLOC_FL_KEEP_SIZE = 0x01

// doWrite - encrypt "data" and write it to plaintext offset "off"
//
// Arguments do not have to be block-aligned, read-modify-write is
// performed internally as neccessary
//
// Called by Write() for normal writing,
// and by Truncate() to rewrite the last file block.
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
	blocks := f.cfs.ExplodePlainRange(uint64(off), uint64(len(data)))
	for _, b := range blocks {

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
			blockData = f.cfs.MergeBlocks(oldData, blockData, int(b.Skip))
			cryptfs.Debug.Printf("len(oldData)=%d len(blockData)=%d\n", len(oldData), len(blockData))
		}

		blockOffset, blockLen := b.CiphertextRange()
		blockData = f.cfs.EncryptBlock(blockData, b.BlockNo, f.header.Id)
		cryptfs.Debug.Printf("ino%d: Writing %d bytes to block #%d, md5=%s\n",
			f.ino, uint64(len(blockData))-f.cfs.BlockOverhead(), b.BlockNo, cryptfs.Debug.Md5sum(blockData))

		// Prevent partially written (=corrupt) blocks by preallocating the space beforehand
		f.fdLock.Lock()
		err := fallocateRetry(int(f.fd.Fd()), FALLOC_FL_KEEP_SIZE, int64(blockOffset), int64(blockLen))
		f.fdLock.Unlock()
		if err != nil {
			cryptfs.Warn.Printf("doWrite: fallocateRetry failed: %s\n", err.Error())
			status = fuse.ToStatus(err)
			break
		}

		// Write
		f.fdLock.Lock()
		_, err = f.fd.WriteAt(blockData, int64(blockOffset))
		f.fdLock.Unlock()
		if err != nil {
			cryptfs.Warn.Printf("doWrite: Write failed: %s\n", err.Error())
			status = fuse.ToStatus(err)
			break
		}
		written += uint32(b.Length)
	}
	return written, status
}

// Write - FUSE call
func (f *file) Write(data []byte, off int64) (uint32, fuse.Status) {
	cryptfs.Debug.Printf("ino%d: FUSE Write: offset=%d length=%d\n", f.ino, off, len(data))

	fi, err := f.fd.Stat()
	if err != nil {
		cryptfs.Warn.Printf("Write: Fstat failed: %v\n", err)
		return 0, fuse.ToStatus(err)
	}
	plainSize := f.cfs.CipherSizeToPlainSize(uint64(fi.Size()))
	if f.createsHole(plainSize, off) {
		status := f.zeroPad(plainSize)
		if status != fuse.OK {
			cryptfs.Warn.Printf("zeroPad returned error %v\n", status)
			return 0, status
		}
	}
	return f.doWrite(data, off)
}

// Release - FUSE call, forget file
func (f *file) Release() {
	f.fdLock.Lock()
	f.fd.Close()
	f.fdLock.Unlock()
}

// Flush - FUSE call
func (f *file) Flush() fuse.Status {
	f.fdLock.Lock()

	// Since Flush() may be called for each dup'd fd, we don't
	// want to really close the file, we just want to flush. This
	// is achieved by closing a dup'd fd.
	newFd, err := syscall.Dup(int(f.fd.Fd()))
	f.fdLock.Unlock()

	if err != nil {
		return fuse.ToStatus(err)
	}
	err = syscall.Close(newFd)
	return fuse.ToStatus(err)
}

func (f *file) Fsync(flags int) (code fuse.Status) {
	f.fdLock.Lock()
	r := fuse.ToStatus(syscall.Fsync(int(f.fd.Fd())))
	f.fdLock.Unlock()

	return r
}

func (f *file) Truncate(newSize uint64) fuse.Status {
	// Common case first: Truncate to zero
	if newSize == 0 {
		f.fdLock.Lock()
		err := syscall.Ftruncate(int(f.fd.Fd()), 0)
		f.fdLock.Unlock()
		if err != nil {
			cryptfs.Warn.Printf("Ftruncate(fd, 0) returned error: %v", err)
			return fuse.ToStatus(err)
		}
		// A truncate to zero kills the file header
		f.header = nil
		return fuse.OK
	}

	// We need the old file size to determine if we are growing or shrinking
	// the file
	fi, err := f.fd.Stat()
	if err != nil {
		cryptfs.Warn.Printf("Truncate: Fstat failed: %v\n", err)
		return fuse.ToStatus(err)
	}
	oldSize := f.cfs.CipherSizeToPlainSize(uint64(fi.Size()))
	{
		oldB := float32(oldSize) / float32(f.cfs.PlainBS())
		newB := float32(newSize) / float32(f.cfs.PlainBS())
		cryptfs.Debug.Printf("ino%d: FUSE Truncate from %.2f to %.2f blocks (%d to %d bytes)\n", f.ino, oldB, newB, oldSize, newSize)
	}

	// File grows
	if newSize > oldSize {

		// File was empty, create new header
		if oldSize == 0 {
			err := f.createHeader()
			if err != nil {
				return fuse.ToStatus(err)
			}
		}

		blocks := f.cfs.ExplodePlainRange(oldSize, newSize-oldSize)
		for _, b := range blocks {
			// First and last block may be partial
			if b.IsPartial() {
				off, _ := b.PlaintextRange()
				off += b.Skip
				_, status := f.doWrite(make([]byte, b.Length), int64(off))
				if status != fuse.OK {
					return status
				}
			} else {
				off, length := b.CiphertextRange()
				f.fdLock.Lock()
				err := syscall.Ftruncate(int(f.fd.Fd()), int64(off+length))
				f.fdLock.Unlock()
				if err != nil {
					cryptfs.Warn.Printf("grow Ftruncate returned error: %v", err)
					return fuse.ToStatus(err)
				}
			}
		}
		return fuse.OK
	} else {
		// File shrinks
		blockNo := f.cfs.PlainOffToBlockNo(newSize)
		cipherOff := f.cfs.BlockNoToCipherOff(blockNo)
		plainOff := f.cfs.BlockNoToPlainOff(blockNo)
		lastBlockLen := newSize - plainOff
		var data []byte
		if lastBlockLen > 0 {
			var status fuse.Status
			data, status = f.doRead(plainOff, lastBlockLen)
			if status != fuse.OK {
				cryptfs.Warn.Printf("shrink doRead returned error: %v", err)
				return status
			}
		}
		// Truncate down to last complete block
		f.fdLock.Lock()
		err = syscall.Ftruncate(int(f.fd.Fd()), int64(cipherOff))
		f.fdLock.Unlock()
		if err != nil {
			cryptfs.Warn.Printf("shrink Ftruncate returned error: %v", err)
			return fuse.ToStatus(err)
		}
		// Append partial block
		if lastBlockLen > 0 {
			_, status := f.doWrite(data, int64(plainOff))
			return status
		}
		return fuse.OK
	}
}

func (f *file) Chmod(mode uint32) fuse.Status {
	f.fdLock.Lock()
	r := fuse.ToStatus(f.fd.Chmod(os.FileMode(mode)))
	f.fdLock.Unlock()

	return r
}

func (f *file) Chown(uid uint32, gid uint32) fuse.Status {
	f.fdLock.Lock()
	r := fuse.ToStatus(f.fd.Chown(int(uid), int(gid)))
	f.fdLock.Unlock()

	return r
}

func (f *file) GetAttr(a *fuse.Attr) fuse.Status {
	cryptfs.Debug.Printf("file.GetAttr()\n")
	st := syscall.Stat_t{}
	f.fdLock.Lock()
	err := syscall.Fstat(int(f.fd.Fd()), &st)
	f.fdLock.Unlock()
	if err != nil {
		return fuse.ToStatus(err)
	}
	a.FromStat(&st)
	a.Size = f.cfs.CipherSizeToPlainSize(a.Size)

	return fuse.OK
}

// Allocate - FUSE call, fallocate(2)
func (f *file) Allocate(off uint64, sz uint64, mode uint32) fuse.Status {
	cryptfs.Warn.Printf("Fallocate is not supported, returning ENOSYS - see https://github.com/rfjakob/gocryptfs/issues/1\n")
	return fuse.ENOSYS
}

const _UTIME_OMIT = ((1 << 30) - 2)

func (f *file) Utimens(a *time.Time, m *time.Time) fuse.Status {
	ts := make([]syscall.Timespec, 2)

	if a == nil {
		ts[0].Nsec = _UTIME_OMIT
	} else {
		ts[0].Sec = a.Unix()
	}

	if m == nil {
		ts[1].Nsec = _UTIME_OMIT
	} else {
		ts[1].Sec = m.Unix()
	}

	f.fdLock.Lock()
	fn := fmt.Sprintf("/proc/self/fd/%d", f.fd.Fd())
	err := syscall.UtimesNano(fn, ts)
	f.fdLock.Unlock()
	return fuse.ToStatus(err)
}
