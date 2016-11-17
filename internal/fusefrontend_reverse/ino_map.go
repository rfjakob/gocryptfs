package fusefrontend_reverse

import (
	"sync/atomic"
)

func newInoGen() *inoGenT {
	var ino uint64 = 1
	return &inoGenT{&ino}
}

type inoGenT struct {
	ino *uint64
}

// Get the next inode counter value
func (i *inoGenT) next() uint64 {
	return atomic.AddUint64(i.ino, 1)
}
