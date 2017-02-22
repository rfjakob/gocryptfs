package speed

/*
Make the "-speed" benchmarks also accessible to the standard test system.
Example run:

$ go test -bench .
BenchmarkStupidGCM-2   	  100000	     22552 ns/op	 181.62 MB/s
BenchmarkGoGCM-2       	   20000	     81871 ns/op	  50.03 MB/s
BenchmarkAESSIV-2      	   10000	    104623 ns/op	  39.15 MB/s
PASS
ok  	github.com/rfjakob/gocryptfs/internal/speed	6.022s
*/

import (
	"testing"
)

func BenchmarkStupidGCM(b *testing.B) {
	bStupidGCM(b)
}

func BenchmarkGoGCM(b *testing.B) {
	bGoGCM(b)
}

func BenchmarkAESSIV(b *testing.B) {
	bAESSIV(b)
}
