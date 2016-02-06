package nametransform

import "sync"

// A simple one-entry DirIV cache
type dirIVCache struct {
	// Invalidated?
	cleared bool
	// The DirIV
	iv []byte
	// Directory the DirIV belongs to
	dir string
	// Ecrypted version of "dir"
	translatedDir string
	// Synchronisation
	lock sync.RWMutex
}

// lookup - fetch entry for "dir" from the cache
func (c *dirIVCache) lookup(dir string) (bool, []byte, string) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if !c.cleared && c.dir == dir {
		return true, c.iv, c.translatedDir
	}
	return false, nil, ""
}

// store - write entry for "dir" into the caches
func (c *dirIVCache) store(dir string, iv []byte, translatedDir string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.cleared = false
	c.iv = iv
	c.dir = dir
	c.translatedDir = translatedDir
}

func (c *dirIVCache) Clear() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.cleared = true
}
