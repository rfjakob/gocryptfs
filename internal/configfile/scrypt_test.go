package configfile

import (
	"fmt"
	"testing"
)

/*
$ time go test -bench . -run none
goos: linux
goarch: amd64
pkg: github.com/rfjakob/gocryptfs/v2/internal/configfile
cpu: Intel(R) Core(TM) i5-3470 CPU @ 3.20GHz
BenchmarkScryptN/10-4         	     339	   3488649 ns/op	 1053167 B/op	      22 allocs/op ... 3ms+1MiB
BenchmarkScryptN/11-4         	     175	   6816072 ns/op	 2101742 B/op	      22 allocs/op
BenchmarkScryptN/12-4         	      87	  13659346 ns/op	 4198898 B/op	      22 allocs/op
BenchmarkScryptN/13-4         	      43	  27443071 ns/op	 8393209 B/op	      22 allocs/op
BenchmarkScryptN/14-4         	      21	  56931664 ns/op	16781820 B/op	      22 allocs/op
BenchmarkScryptN/15-4         	      10	 108494502 ns/op	33559027 B/op	      22 allocs/op
BenchmarkScryptN/16-4         	       5	 217347137 ns/op	67113465 B/op	      22 allocs/op  ... 217ms+67MiB
BenchmarkScryptN/17-4         	       3	 449680138 ns/op	134222362 B/op	      22 allocs/op
BenchmarkScryptN/18-4         	       2	 867481653 ns/op	268440064 B/op	      22 allocs/op
BenchmarkScryptN/19-4         	       1	1738085333 ns/op	536875536 B/op	      23 allocs/op
BenchmarkScryptN/20-4         	       1	3508224867 ns/op	1073746448 B/op	      23 allocs/op
BenchmarkScryptN/21-4         	       1	9536561994 ns/op	2147488272 B/op	      23 allocs/op
BenchmarkScryptN/22-4         	       1	16937072495 ns/op	4294971920 B/op	      23 allocs/op
PASS
ok  	github.com/rfjakob/gocryptfs/v2/internal/configfile	47.545s
*/

func BenchmarkScryptN(b *testing.B) {
	for n := 10; n <= 20; n++ {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			benchmarkScryptN(b, n)
		})
	}
}

func benchmarkScryptN(b *testing.B, n int) {
	kdf := NewScryptKDF(n)
	for i := 0; i < b.N; i++ {
		kdf.DeriveKey(testPw)
	}
	b.ReportAllocs()
}
