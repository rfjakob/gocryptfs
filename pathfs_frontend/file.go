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
}

func NewFile(fd *os.File, writeOnly bool, cfs *cryptfs.CryptFS) nodefs.File {
	return &file{
		fd: fd,
		writeOnly: writeOnly,
		cfs: cfs,
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

// Read - FUSE call
func (f *file) Read(buf []byte, off int64) (resultData fuse.ReadResult, code fuse.Status) {
	cryptfs.Debug.Printf("\n\nGot read request: len=%d off=%d\n", len(buf), off)

	if f.writeOnly {
		return nil, fuse.EBADF
	}

	// Read the backing ciphertext in one go
	alignedOffset, alignedLength, skip := f.cfs.CiphertextRange(uint64(off), uint64(len(buf)))
	ciphertext := make([]byte, int(alignedLength))
	_, err := f.fd.ReadAt(ciphertext, int64(alignedOffset))
	if err != nil && err != io.EOF {
		cryptfs.Warn.Printf("Read error: %s\n", err.Error())
		return nil, fuse.ToStatus(err)
	}

	// Decrypt it
	plaintext, err := f.cfs.DecryptBlocks(ciphertext)
	if err != nil {
		cryptfs.Warn.Printf("Decryption error: %s\n", err.Error())
		return nil, fuse.EIO
	}

	// Crop down to the relevant part
	var out []byte
	lenHave := len(plaintext)
	lenWant := skip + len(buf)
	if lenHave > lenWant {
		out = plaintext[skip:skip + len(buf)]
	} else if lenHave > skip {
		out = plaintext[skip:lenHave]
	}
	// else: out stays empty

	fmt.Printf("Read: returning %d bytes\n", len(plaintext))

	return fuse.ReadResultData(out), fuse.OK
}

// Write - FUSE call
func (f *file) Write(data []byte, off int64) (uint32, fuse.Status) {
	var written uint32
	var status fuse.Status
	dataBuf := bytes.NewBuffer(data)
	blocks := f.cfs.SplitRange(uint64(off), uint64(len(data)))
	for _, b := range(blocks) {

		blockData := dataBuf.Next(int(b.Length))

		// Incomplete block -> Read-Modify-Write
		if b.IsPartial() {
			// Read
			oldData := make([]byte, f.cfs.PlainBS())
			o, _ := b.PlaintextRange()
			res, status := f.Read(oldData, int64(o))
			oldData, _ = res.Bytes(oldData)
			if status != fuse.OK {
				return written, status
			}
			// Modify
			blockData = f.cfs.MergeBlocks(oldData, blockData, int(b.Offset))
		}
		// Write
		blockOffset, _ := b.CiphertextRange()
		blockData = f.cfs.EncryptBlock(blockData)
		_, err := f.fd.WriteAt(blockData, int64(blockOffset))

		if err != nil {
			cryptfs.Warn.Printf("Write failed: %s\n", err.Error())
			status = fuse.ToStatus(err)
			break
		}
		written += uint32(b.Length)
	}

	return written, status
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

func (f *file) Truncate(size uint64) fuse.Status {
	f.lock.Lock()
	r := fuse.ToStatus(syscall.Ftruncate(int(f.fd.Fd()), int64(size)))
	f.lock.Unlock()

	return r
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
	st := syscall.Stat_t{}
	f.lock.Lock()
	err := syscall.Fstat(int(f.fd.Fd()), &st)
	f.lock.Unlock()
	if err != nil {
		return fuse.ToStatus(err)
	}
	a.FromStat(&st)

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
