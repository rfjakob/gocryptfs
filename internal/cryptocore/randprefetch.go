package cryptocore

import (
	"bytes"
	"log"
	"sync"
)

/*
Number of bytes to prefetch.

512 looks like a good compromise between throughput and latency:
Benchmark16-2      	 3000000	       567 ns/op	  28.18 MB/s
Benchmark64-2      	 5000000	       293 ns/op	  54.51 MB/s
Benchmark128-2     	10000000	       220 ns/op	  72.48 MB/s
Benchmark256-2     	10000000	       210 ns/op	  76.17 MB/s
Benchmark512-2     	10000000	       191 ns/op	  83.75 MB/s
Benchmark1024-2    	10000000	       171 ns/op	  93.48 MB/s
Benchmark2048-2    	10000000	       165 ns/op	  96.45 MB/s
Benchmark4096-2    	10000000	       165 ns/op	  96.58 MB/s
Benchmark40960-2   	10000000	       147 ns/op	 108.82 MB/s
*/
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
