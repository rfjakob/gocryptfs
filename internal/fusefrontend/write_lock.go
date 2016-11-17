package fusefrontend

import (
	"sync"
	"sync/atomic"
	"syscall"
)

// DevInoStruct uniquely identifies a backing file through device number and
// inode number.
type DevInoStruct struct {
	dev uint64
	ino uint64
}

// DevInoFromStat fills a new DevInoStruct with the passed Stat_t info
func DevInoFromStat(st *syscall.Stat_t) DevInoStruct {
	// Explicit cast to uint64 to prevent build problems on 32-bit platforms
	return DevInoStruct{
		dev: uint64(st.Dev),
		ino: uint64(st.Ino),
	}
}

func init() {
	openFileMap.entries = make(map[DevInoStruct]*openFileEntryT)
}

// wlock - serializes write accesses to each file (identified by inode number)
// Writing partial blocks means we have to do read-modify-write cycles. We
// really don't want concurrent writes there.
// Concurrent full-block writes could actually be allowed, but are not to
// keep the locking simple.
var openFileMap openFileMapT

// wlockMap - usage:
// 1) register
// 2) lock ... unlock ...
// 3) unregister
type openFileMapT struct {
	// opCount counts writeLock.Lock() calls. As every operation that modifies a file should
	// call it, this effectively serves as a write-operation counter.
	// The variable is accessed without holding any locks so atomic operations
	// must be used. It must be the first element of the struct to guarantee
	// 64-bit alignment.
	opCount uint64
	// Protects map access
	sync.Mutex
	entries map[DevInoStruct]*openFileEntryT
}

type opCountMutex struct {
	sync.Mutex
	// Points to the opCount variable of the parent openFileMapT
	opCount *uint64
}

func (o *opCountMutex) Lock() {
	o.Mutex.Lock()
	atomic.AddUint64(o.opCount, 1)
}

// refCntMutex - mutex with reference count
type openFileEntryT struct {
	// Reference count
	refCnt int
	// Write lock for this inode
	writeLock *opCountMutex
	// ID is the file ID in the file header.
	ID     []byte
	IDLock sync.RWMutex
}

// register creates an entry for "ino", or incrementes the reference count
// if the entry already exists.
func (w *openFileMapT) register(di DevInoStruct) *openFileEntryT {
	w.Lock()
	defer w.Unlock()

	r := w.entries[di]
	if r == nil {
		o := opCountMutex{opCount: &w.opCount}
		r = &openFileEntryT{writeLock: &o}
		w.entries[di] = r
	}
	r.refCnt++
	return r
}

// unregister decrements the reference count for "di" and deletes the entry if
// the reference count has reached 0.
func (w *openFileMapT) unregister(di DevInoStruct) {
	w.Lock()
	defer w.Unlock()

	r := w.entries[di]
	r.refCnt--
	if r.refCnt == 0 {
		delete(w.entries, di)
	}
}
