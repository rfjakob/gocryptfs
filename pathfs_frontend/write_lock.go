package pathfs_frontend

import (
	"sync"
)

func init() {
	wlock.m = make(map[uint64]*refCntMutex)
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
	mapMutex sync.RWMutex
	m        map[uint64]*refCntMutex
}

func (w *wlockMap) register(ino uint64) {
	w.mapMutex.Lock()
	r := w.m[ino]
	if r == nil {
		r = &refCntMutex{}
		w.m[ino] = r
	}
	r.refCnt++ // this must happen inside the mapMutex lock
	w.mapMutex.Unlock()
}

func (w *wlockMap) unregister(ino uint64) {
	w.mapMutex.Lock()
	r := w.m[ino]
	r.refCnt--
	if r.refCnt == 0 {
		delete(w.m, ino)
	}
	w.mapMutex.Unlock()
}

func (w *wlockMap) lock(ino uint64) {
	w.mapMutex.RLock()
	r := w.m[ino]
	w.mapMutex.RUnlock()
	r.Lock() // this can take a long time - execute outside the mapMutex lock
}

func (w *wlockMap) unlock(ino uint64) {
	w.mapMutex.RLock()
	r := w.m[ino]
	w.mapMutex.RUnlock()
	r.Unlock()
}

// refCntMutex - mutex with reference count
type refCntMutex struct {
	sync.Mutex
	refCnt int
}
