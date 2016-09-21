package fusefrontend_reverse

import (
	"sync/atomic"
)

func NewInoGen() *inoGenT {
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

type devIno struct {
	dev uint64
	ino uint64
}
