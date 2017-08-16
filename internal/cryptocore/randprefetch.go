package cryptocore

import (
	"bytes"
	"log"
	"sync"
)

// Number of bytes to prefetch.
// 512 looks like a good compromise between throughput and latency - see
// randsize_test.go for numbers.
const prefetchN = 512

func init() {
	randPrefetcher.refill = make(chan []byte)
	go randPrefetcher.refillWorker()
}

type randPrefetcherT struct {
	sync.Mutex
	buf    bytes.Buffer
	refill chan []byte
}

func (r *randPrefetcherT) read(want int) (out []byte) {
	out = make([]byte, want)
	r.Lock()
	// Note: don't use defer, it slows us down!
	have, err := r.buf.Read(out)
	if have == want && err == nil {
		r.Unlock()
		return out
	}
	// Buffer was empty -> re-fill
	fresh := <-r.refill
	if len(fresh) != prefetchN {
		log.Panicf("randPrefetcher: refill: got %d bytes instead of %d", len(fresh), prefetchN)
	}
	r.buf.Reset()
	r.buf.Write(fresh)
	have, err = r.buf.Read(out)
	if have != want || err != nil {
		log.Panicf("randPrefetcher could not satisfy read: have=%d want=%d err=%v", have, want, err)
	}
	r.Unlock()
	return out
}

func (r *randPrefetcherT) refillWorker() {
	for {
		r.refill <- RandBytes(prefetchN)
	}
}

var randPrefetcher randPrefetcherT
