//go:build go1.7
// +build go1.7

// ^^^^^^^^^^^^ we use the "sub-benchmark" feature that was added in Go 1.7

package cryptocore

import (
	"fmt"
	"testing"
)

/*
The throughput we get from /dev/urandom / getentropy depends a lot on the used
block size. Results on my Pentium G630 running Linux 4.11:

BenchmarkRandSize/16-2         	 3000000	       571 ns/op	  27.98 MB/s
BenchmarkRandSize/32-2         	 3000000	       585 ns/op	  54.66 MB/s
BenchmarkRandSize/64-2         	 2000000	       860 ns/op	  74.36 MB/s
BenchmarkRandSize/128-2        	 1000000	      1197 ns/op	 106.90 MB/s
BenchmarkRandSize/256-2        	 1000000	      1867 ns/op	 137.06 MB/s
BenchmarkRandSize/512-2        	  500000	      3187 ns/op	 160.61 MB/s
BenchmarkRandSize/1024-2       	  200000	      5888 ns/op	 173.91 MB/s
BenchmarkRandSize/2048-2       	  100000	     11554 ns/op	 177.25 MB/s
BenchmarkRandSize/4096-2       	  100000	     22523 ns/op	 181.86 MB/s
BenchmarkRandSize/8192-2       	   30000	     43111 ns/op	 190.02 MB/s

Results are similar when testing with dd, so this is not due to Go allocation
overhead: dd if=/dev/urandom bs=16 count=100000 of=/dev/null
*/
func BenchmarkUrandomBlocksize(b *testing.B) {
	for s := 16; s <= 8192; s *= 2 {
		title := fmt.Sprintf("%d", s)
		b.Run(title, func(b *testing.B) {
			b.SetBytes(int64(s))
			for i := 0; i < b.N; i++ {
				RandBytes(s)
			}
		})
	}
}
