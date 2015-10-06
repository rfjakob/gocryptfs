GoCryptFS
=========
An encrypted overlay filesystem focused on security and correctness.

gocryptfs is built on top the excellent
[go-fuse](https://github.com/hanwen/go-fuse) FUSE library and its
LoopbackFileSystem API.

This project was inspired by [EncFS](https://github.com/vgough/encfs)
and strives to fix its security issues (see EncFS tickets 9, 13, 14, 16).
For details on the security of GoCryptFS see the
[SECURITY.md](https://github.com/rfjakob/gocryptfs/blob/master/SECURITY.md)
document.

Current Status
--------------
* First public release
* Feature-Complete
* Passes the xfstests "generic" tests

Install
-------

	go get github.com/rfjakob/gocryptfs

Performance
-----------

 * 28 bytes of storage overhead per block (16 bytes auth tag, 12 byte nonce)
 * uses openssl through [spacemonkeygo/openssl](https://github.com/spacemonkeygo/openssl)
   for a 3x speedup compared to `crypto/cipher` (see [go-vs-openssl.md](https://github.com/rfjakob/gocryptfs/blob/master/openssl_benchmark/go-vs-openssl.md)) for details

Run `./benchmark.bash` to run the test suite and the streaming read/write
benchmark. The benchmark is run twice, first with native Go crypto and
second using openssl.

The output should look like this:

	$ ./benchmark.bash
	[...]
	BenchmarkStreamWrite	     100	  11816665 ns/op	  88.74 MB/s
	BenchmarkStreamRead 	     200	   7848155 ns/op	 133.61 MB/s
	ok  	github.com/rfjakob/gocryptfs	9.407s

