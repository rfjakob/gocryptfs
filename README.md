GoCryptFS [![Build Status](https://travis-ci.org/rfjakob/gocryptfs.svg?branch=master)](https://travis-ci.org/rfjakob/gocryptfs) ![Release Status](https://img.shields.io/badge/status-beta-yellow.svg?style=flat)
==============
An encrypted overlay filesystem written in Go.

gocryptfs is built on top the excellent
[go-fuse](https://github.com/hanwen/go-fuse) FUSE library and its
LoopbackFileSystem API.

This project was inspired by [EncFS](https://github.com/vgough/encfs)
and strives to fix its security issues (see EncFS tickets 9, 13, 14, 16).
For details on the security of gocryptfs see the
[SECURITY.md](SECURITY.md) document.

Current Status
--------------
* Feature-complete and working
* Passes the fuse-xfstests "generic" tests with one exception, results: [XFSTESTS.md](XFSTESTS.md)
 * A lot of work has gone into this. The testing has found bugs in gocryptfs
   as well as in go-fuse.
 * The one exception is generic/035. This is a limitation in go-fuse,
   check out https://github.com/hanwen/go-fuse/issues/55 for details.
* However, gocryptfs needs more real-world testing - please report any issues via github.
* Only Linux operation has been tested. Help wanted for Mac OS X verification.

Install
-------

	$ go get github.com/rfjakob/gocryptfs

Use
---

Quickstart:

	$ mkdir cipher plain
	$ $GOPATH/bin/gocryptfs --init cipher
	  [...]
	$ $GOPATH/bin/gocryptfs cipher plain
	  [...]
	$ echo test > plain/test.txt
	$ ls -l cipher
	  total 8
	  -rw-rw-r--. 1 user  user   33  7. Okt 23:23 0ao8Hyyf1A-A88sfNvkUxA==
	  -rw-rw-r--. 1 user  user  233  7. Okt 23:23 gocryptfs.conf
	$ fusermount -u plain

See [MANPAGE.md](MANPAGE.md) for a description of available options.

Storage Overhead
----------------

* Empty files take 0 bytes on disk
* 18 byte file header for non-empty files (2 bytes version, 16 bytes random file id)
* 28 bytes of storage overhead per 4kB block (12 byte nonce, 16 bytes auth tag)

Performance
-----------

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

Changelog
---------

v0.4 (in progress)
* Add `--plaintextnames` command line option
 * Can only be used in conjunction with `--init` and disables filename encryption
   (added on user request)
* Add `FeatureFlags` config file paramter
 * This is a config format change, hence the on-disk format is incremented
 * Used for ext4-style filesystem feature flags. This should help avoid future
   format changes.
* On-disk format 2

v0.3
* Add file header that contains a random id to authenticate blocks
 * This is an on-disk-format change
* On-disk format 1

v0.2
* Replace bash daemonization wrapper with native Go implementation
* Better user feedback on mount failures

v0.1
* First release
* On-disk format 0

See https://github.com/rfjakob/gocryptfs/releases for the release dates
and associated tags.
