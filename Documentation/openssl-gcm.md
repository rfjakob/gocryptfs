Go builtin GCM vs OpenSSL
=========================

OpenSSL is over four times faster than Go's built-in GCM implementation.

```
$ cd internal/stupidgcm
$ go test -bench .
PASS
Benchmark4kEncStupidGCM-2	   50000	     25860 ns/op	 158.39 MB/s
Benchmark4kEncGoGCM-2    	   10000	    116050 ns/op	  35.29 MB/s
ok  	github.com/rfjakob/gocryptfs/internal/stupidgcm	3.667s
```
