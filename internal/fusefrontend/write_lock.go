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

func DevInoFromStat(st *syscall.Stat_t) DevInoStruct {
	// Explicit cast to uint64 to prevent build problems on 32-bit platforms
	return DevInoStruct{
		dev: uint64(st.Dev),
		ino: uint64(st.Ino),
	}
}

func init() {
	wlock.inodeLocks = make(map[DevInoStruct]*refCntMutex)
}

// wlock - serializes write accesses to each file (identified by inode number)
// Writing partial blocks means we have to do read-modify-write cycles. We
// really don't want concurrent writes there.
// Concurrent full-block writes could actually be allowed, but are not to
// keep the locking simple.
var wlock wlockMap

// wlockMap - usage:
// 1) register
// 2) lock ... unlock ...
// 3) unregister
type wlockMap struct {
	// opCount counts lock() calls. As every operation that modifies a file should
	// call it, this effectively serves as a write-operation counter.
	// The variable is accessed without holding any locks so atomic operations
	// must be used. It must be the first element of the struct to guarantee
	// 64-bit alignment.
	opCount uint64
	// Protects map access
	sync.Mutex
	inodeLocks map[DevInoStruct]*refCntMutex
}

// refCntMutex - mutex with reference count
type refCntMutex struct {
	// Write lock for this inode
	sync.Mutex
	// Reference count
	refCnt int
}

// register creates an entry for "ino", or incrementes the reference count
// if the entry already exists.
func (w *wlockMap) register(di DevInoStruct) {
	w.Lock()
	defer w.Unlock()

	r := w.inodeLocks[di]
	if r == nil {
		r = &refCntMutex{}
		w.inodeLocks[di] = r
	}
	r.refCnt++
}

// unregister decrements the reference count for "di" and deletes the entry if
// the reference count has reached 0.
func (w *wlockMap) unregister(di DevInoStruct) {
	w.Lock()
	defer w.Unlock()

	r := w.inodeLocks[di]
	r.refCnt--
	if r.refCnt == 0 {
		delete(w.inodeLocks, di)
	}
}

// lock retrieves the entry for "di" and locks it.
func (w *wlockMap) lock(di DevInoStruct) {
	atomic.AddUint64(&w.opCount, 1)
	w.Lock()
	r := w.inodeLocks[di]
	w.Unlock()
	// this can take a long time - execute outside the wlockMap lock
	r.Lock()
}

// unlock retrieves the entry for "di" and unlocks it.
func (w *wlockMap) unlock(di DevInoStruct) {
	w.Lock()
	r := w.inodeLocks[di]
	w.Unlock()
	r.Unlock()
}
