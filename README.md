GoCryptFS
=========
An encrypted overlay filesystem focused on security and correctness.

gocryptfs is built on top the excellent
[go-fuse](https://github.com/hanwen/go-fuse) FUSE library and its
LoopbackFileSystem API.

This project was inspired by [EncFS](https://github.com/vgough/encfs)
and strives to fix its security issues (see EncFS tickets 9, 13, 14, 16).
For details on the security of GoCryptFS see the
[SECURITY.md](SECURITY.md) document.

Current Status
--------------
* First public release
* Feature-complete
* Passes the fuse-xfstests "generic" tests with one exception, results: [XFSTESTS.md](XFSTESTS.md)
 * A lot of work has gone into this. The testing has found bugs in gocryptfs
   as well as in go-fuse.
 * The one exceptions generic/035. This is a limitation in go-fuse,
   check out https://github.com/hanwen/go-fuse/issues/55 for details.
* However, gocryptfs needs more real-world testing - please report any issues via github.
* Only Linux operation has been tested. Help wanted for a Mac OS X port.

Install
-------

	$ go get github.com/rfjakob/gocryptfs/gocryptfs_main

Use
---

	$ mkdir cipher plain
	$ alias gocryptfs="$GOPATH/src/github.com/rfjakob/gocryptfs/gocryptfs"
	$ gocryptfs --init cipher
	  [...]
	$ gocryptfs cipher plain
	  [...]
	$ echo test > plain/test.txt
	$ ls -l cipher
	  total 8
	  -rw-rw-r--. 1 user  user   33  7. Okt 23:23 0ao8Hyyf1A-A88sfNvkUxA==
	  -rw-rw-r--. 1 user  user  233  7. Okt 23:23 gocryptfs.conf

Performance
-----------

 * 28 bytes of storage overhead per block (16 bytes auth tag, 12 byte nonce)
 * uses openssl through [spacemonkeygo/openssl](https://github.com/spacemonkeygo/openssl)
   for a 3x speedup compared to `crypto/cipher` (see [go-vs-openssl.md](openssl_benchmark/go-vs-openssl.md) for details

Run `./benchmark.bash` to run the test suite and the streaming read/write
benchmark. The benchmark is run twice, first with native Go crypto and
second using openssl.

The output should look like this:

	$ ./benchmark.bash
	[...]
	BenchmarkStreamWrite	     100	  11816665 ns/op	  88.74 MB/s
	BenchmarkStreamRead 	     200	   7848155 ns/op	 133.61 MB/s
	ok  	github.com/rfjakob/gocryptfs	9.407s

