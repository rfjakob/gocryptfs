package nametransform

import "sync"

// Single-entry DirIV cache. Stores the directory IV and the encrypted
// path.
type dirIVCache struct {
	// Directory the DirIV belongs to
	dir string

	// The DirIV
	iv []byte
	// Ecrypted version of "dir"
	cDir string

	// Invalidated?
	cleared bool
	sync.RWMutex
}

// lookup - fetch entry for "dir" from the cache
func (c *dirIVCache) lookup(dir string) ([]byte, string) {
	c.RLock()
	defer c.RUnlock()
	if c.cleared || c.dir != dir {
		return nil, ""
	}
	return c.iv, c.cDir
}

// store - write entry for "dir" into the cache
func (c *dirIVCache) store(dir string, iv []byte, cDir string) {
	c.Lock()
	defer c.Unlock()
	c.cleared = false
	c.iv = iv
	c.dir = dir
	c.cDir = cDir
}

// Clear ... clear the cache.
// Exported because it is called from fusefrontend when directories are
// renamed or deleted.
func (c *dirIVCache) Clear() {
	c.Lock()
	defer c.Unlock()
	c.cleared = true
}
