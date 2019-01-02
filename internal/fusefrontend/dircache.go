package fusefrontend

import (
	"fmt"
	"log"
	"sync"
	"syscall"
	"time"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

type dirCacheStruct struct {
	sync.Mutex
	// relative plaintext path to the directory
	dirRelPath string
	// fd to the directory (opened with O_PATH!)
	fd int
	// content of gocryptfs.diriv in this directory
	iv []byte
	// on the first Lookup(), the expire thread is stared, and this is set
	// to true.
	expireThreadRunning bool
}

// Clear clears the cache contents.
func (d *dirCacheStruct) Clear() {
	d.Lock()
	defer d.Unlock()
	d.doClear()
}

// doClear closes the fd and clears the cache contents.
// Caller must hold d.Lock()!
func (d *dirCacheStruct) doClear() {
	// An earlier clear may have already closed the fd, or the cache
	// has never been filled (fd is 0 in that case).
	if d.fd > 0 {
		err := syscall.Close(d.fd)
		if err != nil {
			tlog.Warn.Printf("dirCache.Clear: Close failed: %v", err)
		}
	}
	d.fd = -1
	d.dirRelPath = ""
	d.iv = nil
}

// Store the entry in the cache. The passed "fd" will be Dup()ed, and the caller
// can close their copy at will.
func (d *dirCacheStruct) Store(dirRelPath string, fd int, iv []byte) {
	if fd <= 0 || len(iv) != nametransform.DirIVLen {
		log.Panicf("Store sanity check failed: fd=%d len=%d", fd, len(iv))
	}
	d.Lock()
	defer d.Unlock()
	// Close the old fd
	d.doClear()
	fd2, err := syscall.Dup(fd)
	if err != nil {
		tlog.Warn.Printf("dirCache.Store: Dup failed: %v", err)
		return
	}
	d.fd = fd2
	d.dbg("Store: %q %d %x\n", dirRelPath, fd2, iv)
	d.dirRelPath = dirRelPath
	d.iv = iv
	// expireThread is started on the first Lookup()
	if !d.expireThreadRunning {
		d.expireThreadRunning = true
		go d.expireThread()
	}
}

// Lookup checks if relPath is in the cache, and returns and (fd, iv) pair.
// It returns (-1, nil) if not found. The fd is internally Dup()ed and the
// caller must close it when done.
func (d *dirCacheStruct) Lookup(dirRelPath string) (fd int, iv []byte) {
	d.Lock()
	defer d.Unlock()
	if d.fd <= 0 {
		// Cache is empty
		d.dbg("Lookup %q: empty\n", dirRelPath)
		return -1, nil
	}
	if dirRelPath != d.dirRelPath {
		d.dbg("Lookup %q: miss\n", dirRelPath)
		return -1, nil
	}
	fd, err := syscall.Dup(d.fd)
	if err != nil {
		tlog.Warn.Printf("dirCache.Lookup: Dup failed: %v", err)
		return -1, nil
	}
	if fd <= 0 || len(d.iv) != nametransform.DirIVLen {
		log.Panicf("Lookup sanity check failed: fd=%d len=%d", fd, len(d.iv))
	}
	d.dbg("Lookup %q: hit %d %x\n", dirRelPath, fd, d.iv)
	return fd, d.iv
}

// expireThread is started on the first Lookup()
func (d *dirCacheStruct) expireThread() {
	for {
		time.Sleep(1 * time.Second)
		d.Clear()
	}
}

// dbg prints a debug message. Usually disabled.
func (d *dirCacheStruct) dbg(format string, a ...interface{}) {
	const EnableDebugMessages = false
	if EnableDebugMessages {
		fmt.Printf(format, a...)
	}
}
