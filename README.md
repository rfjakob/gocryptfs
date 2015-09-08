GoCryptFS
=========
A minimal encrypted overlay filesystem written in Go.

Inspired by [EncFS](https://github.com/vgough/encfs).

GoCryptFS at the moment has two FUSE frontends:

* The [go-fuse](https://github.com/hanwen/go-fuse) FUSE library using its
  LoopbackFileSystem API
* The FUSE library [bazil.org/fuse](https://github.com/bazil/fuse) plus the
  [ClueFS](https://github.com/airnandez/cluefs) loopback filesystem

A frontend is selected on compile-time by setting `USE_CLUEFS` to true or false
(default false).
Once I decide that one works better for GoCryptFS, the other one
will go away.

Design
------
* Authenticated encryption of file contents using AES-GCM-128
 * Because GCM handles blocks of arbitrary size, there is no special handling for the last file block
 * 4096 byte blocks per default
 * 28 bytes of overhead per block (16 bytes auth tag, 12 byte nonce)
 * uses openssl through [spacemonkeygo/openssl](https://github.com/spacemonkeygo/openssl)
   for a 3x speedup compared to `crypto/cipher` (see [go-vs-openssl.md](https://github.com/rfjakob/gocryptfs/blob/master/openssl_benchmark/go-vs-openssl.md)) for details
* Per-write unique 96 bit nonces
 * starts from a random value (generated at mount time) and counts up
* Flename encryption using AES-CBC-128
 * Padded to 16-byte blocks acc. to [RFC5652 section 6.3](https://tools.ietf.org/html/rfc5652#section-6.3)
 * base64 encoded acc. to [RFC4648 section 5](https://tools.ietf.org/html/rfc4648#section-5)

Current Status
--------------
Not ready for anything but testing and debugging

* File and directory creation and deletion works
* Thread-safe nonce generation works
* Filename and content encryption works
 * Key is set to static all-zero
* Reading and writing works
* Streaming performance is already reasonable
 * But we should be able to get another 50% speedup
* Symlinks and hard links not yet implemented
* Memory usage is insane

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
