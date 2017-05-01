// Package openfiletable maintains a table of currently opened files, identified
// by the device number + inode number pair. This table is used by fusefrontend
// to centrally store the current file ID and to lock files against concurrent
// writes.
package openfiletable

import (
	"sync"
	"sync/atomic"
	"syscall"
)

// QIno = Qualified Inode number.
// Uniquely identifies a backing file through the device number,
// inode number pair.
type QIno struct {
	// Stat_t.{Dev,Ino} is uint64 on 32- and 64-bit Linux
	Dev uint64
	Ino uint64
}

// QInoFromStat fills a new QIno struct with the passed Stat_t info.
func QInoFromStat(st *syscall.Stat_t) QIno {
	return QIno{
		// There are some architectures that use 32-bit values here
		// (darwin, freebsd-32, maybe others). Add and explicit cast to make
		// this function work everywhere.
		Dev: uint64(st.Dev),
		Ino: uint64(st.Ino),
	}
}

// wlock - serializes write accesses to each file (identified by inode number)
// Writing partial blocks means we have to do read-modify-write cycles. We
// really don't want concurrent writes there.
// Concurrent full-block writes could actually be allowed, but are not to
// keep the locking simple.
var t table

func init() {
	t.entries = make(map[QIno]*Entry)
}

type table struct {
	// writeOpCount counts entry.ContentLock.Lock() calls. As every operation that
	// modifies a file should
	// call it, this effectively serves as a write-operation counter.
	// The variable is accessed without holding any locks so atomic operations
	// must be used. It must be the first element of the struct to guarantee
	// 64-bit alignment.
	writeOpCount uint64
	// Protects map access
	sync.Mutex
	// Table entries
	entries map[QIno]*Entry
}

// Entry is an entry in the open file table
type Entry struct {
	// Reference count
	refCount int
	// ContentLock guards the file content from concurrent writes. Every writer
	// must take this lock before modifying the file content.
	ContentLock countingMutex
	// HeaderLock guards the file ID (in this struct) and the file header (on
	// disk). Take HeaderLock.RLock() to make sure the file ID does not change
	// behind your back. If you modify the file ID, you must take
	// HeaderLock.Lock().
	HeaderLock sync.RWMutex
	// ID is the file ID in the file header.
	ID []byte
}

// Register creates an open file table entry for "qi" (or incrementes the
// reference count if the entry already exists) and returns the entry.
func Register(qi QIno) *Entry {
	t.Lock()
	defer t.Unlock()

	e := t.entries[qi]
	if e == nil {
		e = &Entry{}
		t.entries[qi] = e
	}
	e.refCount++
	return e
}

// Unregister decrements the reference count for "qi" and deletes the entry from
// the open file table if the reference count reaches 0.
func Unregister(qi QIno) {
	t.Lock()
	defer t.Unlock()

	e := t.entries[qi]
	e.refCount--
	if e.refCount == 0 {
		delete(t.entries, qi)
	}
}

// countingMutex incrementes t.writeLockCount on each Lock() call.
type countingMutex struct {
	sync.Mutex
}

func (c *countingMutex) Lock() {
	c.Mutex.Lock()
	atomic.AddUint64(&t.writeOpCount, 1)
}

// WriteOpCount returns the write lock counter value. This value is encremented
// each time writeLock.Lock() on a file table entry is called.
func WriteOpCount() uint64 {
	return atomic.LoadUint64(&t.writeOpCount)
}
