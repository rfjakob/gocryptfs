package configfile

import (
	"testing"
)

/*
Results on a 2.7GHz Pentium G630:

gocryptfs/cryptfs$ go test -bench=.
PASS
BenchmarkScrypt10-2	     300	   6021435 ns/op ... 6ms
BenchmarkScrypt11-2	     100	  11861460 ns/op
BenchmarkScrypt12-2	     100	  23420822 ns/op
BenchmarkScrypt13-2	      30	  47666518 ns/op
BenchmarkScrypt14-2	      20	  92561590 ns/op ... 92ms
BenchmarkScrypt15-2	      10	 183971593 ns/op
BenchmarkScrypt16-2	       3	 368506365 ns/op
BenchmarkScrypt17-2	       2	 755502608 ns/op ... 755ms
ok  	github.com/rfjakob/gocryptfs/v2/cryptfs	18.772s
*/

func benchmarkScryptN(n int, b *testing.B) {
	kdf := NewScryptKDF(n)
	for i := 0; i < b.N; i++ {
		kdf.DeriveKey(testPw)
	}
}

func BenchmarkScrypt10(b *testing.B) {
	benchmarkScryptN(10, b)
}

func BenchmarkScrypt11(b *testing.B) {
	benchmarkScryptN(11, b)
}

func BenchmarkScrypt12(b *testing.B) {
	benchmarkScryptN(12, b)
}

func BenchmarkScrypt13(b *testing.B) {
	benchmarkScryptN(13, b)
}

func BenchmarkScrypt14(b *testing.B) {
	benchmarkScryptN(14, b)
}

func BenchmarkScrypt15(b *testing.B) {
	benchmarkScryptN(15, b)
}

func BenchmarkScrypt16(b *testing.B) {
	benchmarkScryptN(16, b)
}

func BenchmarkScrypt17(b *testing.B) {
	benchmarkScryptN(17, b)
}
