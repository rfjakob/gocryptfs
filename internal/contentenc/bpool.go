package contentenc

import (
	"log"
	"sync"
)

// bPool is a byte slice pool
type bPool struct {
	sync.Pool
	sliceLen int
}

func newBPool(sliceLen int) bPool {
	return bPool{
		Pool: sync.Pool{
			New: func() interface{} { return make([]byte, sliceLen) },
		},
		sliceLen: sliceLen,
	}
}

// Put grows the slice "s" to its maximum capacity and puts it into the pool.
func (b *bPool) Put(s []byte) {
	s = s[:cap(s)]
	if len(s) != b.sliceLen {
		log.Panicf("wrong len=%d, want=%d", len(s), b.sliceLen)
	}
	b.Pool.Put(s)
}

// Get returns a byte slice from the pool.
func (b *bPool) Get() (s []byte) {
	s = b.Pool.Get().([]byte)
	if len(s) != b.sliceLen {
		log.Panicf("wrong len=%d, want=%d", len(s), b.sliceLen)
	}
	return s
}
