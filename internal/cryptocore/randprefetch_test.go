package cryptocore

import (
	"bytes"
	"compress/flate"
	"runtime"
	"sync"
	"testing"
)

// TestRandPrefetch hammers the randPrefetcher with 100 goroutines and verifies
// that the result is incompressible
func TestRandPrefetch(t *testing.T) {
	runtime.GOMAXPROCS(10)
	p := 100
	l := 200
	vec := make([][]byte, p)
	var wg sync.WaitGroup
	for i := 0; i < p; i++ {
		wg.Add(1)
		go func(i int) {
			var tmp []byte
			for x := 0; x < l; x++ {
				tmp = append(tmp, randPrefetcher.read(l)...)
			}
			vec[i] = tmp
			wg.Done()
		}(i)
	}
	wg.Wait()
	var b bytes.Buffer
	fw, _ := flate.NewWriter(&b, flate.BestCompression)
	for _, v := range vec {
		fw.Write(v)
	}
	fw.Close()
	if b.Len() < p*l*l {
		t.Errorf("random data should be incompressible, but: in=%d compressed=%d\n", p*l*l, b.Len())
	}
}

func BenchmarkRandPrefetch(b *testing.B) {
	// 16-byte nonces are default since gocryptfs v0.7
	b.SetBytes(16)
	for i := 0; i < b.N; i++ {
		randPrefetcher.read(16)
	}
}
