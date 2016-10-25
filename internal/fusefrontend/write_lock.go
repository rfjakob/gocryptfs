package fusefrontend

import (
	"sync"
	"sync/atomic"
)

func init() {
	wlock.inodeLocks = make(map[uint64]*refCntMutex)
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
	// Counts lock() calls. As every operation that modifies a file should
	// call it, this effectively serves as a write-operation counter.
	// The variable is accessed without holding any locks so atomic operations
	// must be used. It must be the first element of the struct to guarantee
	// 64-bit alignment.
	opCount uint64
	// Protects map access
	sync.Mutex
	inodeLocks map[uint64]*refCntMutex
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
func (w *wlockMap) register(ino uint64) {
	w.Lock()
	defer w.Unlock()

	r := w.inodeLocks[ino]
	if r == nil {
		r = &refCntMutex{}
		w.inodeLocks[ino] = r
	}
	r.refCnt++
}

// unregister decrements the reference count for "ino" and deletes the entry if
// the reference count has reached 0.
func (w *wlockMap) unregister(ino uint64) {
	w.Lock()
	defer w.Unlock()

	r := w.inodeLocks[ino]
	r.refCnt--
	if r.refCnt == 0 {
		delete(w.inodeLocks, ino)
	}
}

// lock retrieves the entry for "ino" and locks it.
func (w *wlockMap) lock(ino uint64) {
	atomic.AddUint64(&w.opCount, 1)
	w.Lock()
	r := w.inodeLocks[ino]
	w.Unlock()
	// this can take a long time - execute outside the wlockMap lock
	r.Lock()
}

// unlock retrieves the entry for "ino" and unlocks it.
func (w *wlockMap) unlock(ino uint64) {
	w.Lock()
	r := w.inodeLocks[ino]
	w.Unlock()
	r.Unlock()
}
