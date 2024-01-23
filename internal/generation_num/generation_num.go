package generation_num

import (
	"sync/atomic"
)

var gen uint64

func Next() uint64 {
	return atomic.AddUint64(&gen, 1)
}
