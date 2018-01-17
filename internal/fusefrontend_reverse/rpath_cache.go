package fusefrontend_reverse

import (
	"sync"
)

// rPathCacheContainer is a simple one entry path cache. Because the dirIV
// is generated deterministically from the directory path, there is no need
// to ever invalidate entries.
type rPathCacheContainer struct {
	sync.Mutex
	// Relative ciphertext path to the directory
	cPath string
	// Relative plaintext path
	pPath string
	// Directory IV of the directory
	dirIV []byte
}

// lookup relative ciphertext path "cPath". Returns dirIV, relative
// plaintext path.
func (c *rPathCacheContainer) lookup(cPath string) ([]byte, string) {
	c.Lock()
	defer c.Unlock()
	if cPath == c.cPath {
		// hit
		return c.dirIV, c.pPath
	}
	// miss
	return nil, ""
}

// store - write entry for the directory at relative ciphertext path "cPath"
// into the cache.
// "dirIV" = directory IV of the directory, "pPath" = relative plaintext path
func (c *rPathCacheContainer) store(cPath string, dirIV []byte, pPath string) {
	c.Lock()
	defer c.Unlock()
	c.cPath = cPath
	c.dirIV = dirIV
	c.pPath = pPath
}

// rPathCache: see rPathCacheContainer above for a detailed description
var rPathCache rPathCacheContainer
