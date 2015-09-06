GoCryptFS
=========
A minimal encrypted overlay filesystem written in Go.

Built on top of the
native Go FUSE library [bazil.org/fuse](https://github.com/bazil/fuse)
and the [ClueFS](https://github.com/airnandez/cluefs) loopback file system.

Inspired by [EncFS](https://github.com/vgough/encfs).

Design
------
* Authenticated encryption of file contents using AES-GCM-128
 * 96 bit nonce that starts from a random value and counts up
 * uses openssl through [spacemonkeygo/openssl](https://github.com/spacemonkeygo/openssl)
   for a 3x speedup compared to `crypto/cipher`
* AES-CBC filename encryption

Current Status
--------------
* Work in progress
* Key is set to static all-zero
* Not ready for anything but testing and debugging

Install
-------

	go get github.com/rfjakob/gocryptfs

Testing
-------
Run `./main_benchmark.bash` to run the test suite and the streaming read/write
benchmark.

The output should look like this:

	$ ./main_benchmark.bash
	+ go build
	+ go test -bench=.
	PASS
	BenchmarkStreamWrite	     100	  14062281 ns/op	  74.57 MB/s
	BenchmarkStreamRead 	     100	  11267741 ns/op	  93.06 MB/s
	ok  	github.com/rfjakob/gocryptfs	7.569s
