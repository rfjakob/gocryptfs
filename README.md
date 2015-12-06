GoCryptFS [![Build Status](https://travis-ci.org/rfjakob/gocryptfs.svg?branch=master)](https://travis-ci.org/rfjakob/gocryptfs) ![Release Status](https://img.shields.io/badge/status-beta-yellow.svg?style=flat)
==============
An encrypted overlay filesystem written in Go.

gocryptfs is built on top the excellent
[go-fuse](https://github.com/hanwen/go-fuse) FUSE library and its
LoopbackFileSystem API.

This project was inspired by [EncFS](https://github.com/vgough/encfs)
and strives to fix its security issues (see EncFS tickets 9, 13, 14, 16).
For details on the security of gocryptfs see the
[SECURITY.md](Documentation/SECURITY.md) document.

Current Status
--------------

Beta. You are advised to keep a backup of your data outside of gocryptfs, in
addition to storing the *master key* in a safe place (the master key is printed
when mounting).

Only Linux is supported at the moment. Help wanted for a Mac OS X port.

Testing
-------

gocryptfs comes with is own test suite that is constantly expanded as features are
added. Run it using `./test.bash`. It takes about 30 seconds and requires FUSE
as it mounts several test filesystems.

In addition, I have ported `xfstests` to FUSE, the result is the
[fuse-xfstests](https://github.com/rfjakob/fuse-xfstests) project. gocryptfs
passes the "generic" tests with one exception, results:  [XFSTESTS.md](Documentation/XFSTESTS.md)

A lot of work has gone into this. The testing has found bugs in gocryptfs
as well as in go-fuse.

The one exception is generic/035, see [go-fuse issue 55](https://github.com/hanwen/go-fuse/issues/55)
for details. While this is a POSIX violation, I do not see any real-world impact.

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

See [MANPAGE.md](Documentation/MANPAGE.md) for a description of available options. If you already
have gocryptfs installed, run `./MANPAGE-render.bash` to bring up the rendered manpage in
the pager (requires pandoc).

Storage Overhead
----------------

* Empty files take 0 bytes on disk
* 18 byte file header for non-empty files (2 bytes version, 16 bytes random file id)
* 28 bytes of storage overhead per 4kB block (12 byte nonce, 16 bytes auth tag)

Performance
-----------

gocryptfs uses openssl through
[spacemonkeygo/openssl](https://github.com/spacemonkeygo/openssl)
for a 3x speedup compared to Go's builtin AES-GCM implementation (see
[go-vs-openssl.md](openssl_benchmark/go-vs-openssl.md) for details).

Run `./benchmark.bash` to run the benchmarks.

The output should look like this:

	./benchmark.bash
	gocryptfs v0.3.1-30-gd69e0df-dirty; on-disk format 2
	PASS
	BenchmarkStreamWrite-2	     100	  12246070 ns/op	  85.63 MB/s
	BenchmarkStreamRead-2 	     200	   9125990 ns/op	 114.90 MB/s
	BenchmarkCreate0B-2   	   10000	    101284 ns/op
	BenchmarkCreate1B-2   	   10000	    178356 ns/op	   0.01 MB/s
	BenchmarkCreate100B-2 	    5000	    361014 ns/op	   0.28 MB/s
	BenchmarkCreate4kB-2  	    5000	    375035 ns/op	  10.92 MB/s
	BenchmarkCreate10kB-2 	    3000	    491071 ns/op	  20.85 MB/s
	ok  	github.com/rfjakob/gocryptfs/integration_tests	17.216s

Changelog
---------

v0.5
* **Stronger filename encryption: DirIV**
 * Each directory gets a random 128 bit file name IV on creation,
   stored in `gocryptfs.diriv`
 * This makes it impossible to identify identically-named files across
   directories
 * A single-entry IV cache brings the performance cost of DirIV close to
   zero for common operations (see performance.txt)
 * This is a forwards-compatible change. gocryptfs v0.5 can mount filesystems
   created by earlier version but not the other way round.
* New command-line option:
 * `-diriv`: Use the new per-directory IV file name encryption (default true)
 * `-scryptn`: allows to set the scrypt cost parameter N. This option
   can be used for faster mounting at the cost of lower brute-force
   resistance. It was mainly added to speed up the automated tests.

v0.4
* New command-line options:
 * `-plaintextnames`: disables filename encryption, added on user request
 * `-extpass`: calls an external program for prompting for the password
 * `-config`: allows to specify a custom gocryptfs.conf path
* Add `FeatureFlags` gocryptfs.conf paramter
 * This is a config format change, hence the on-disk format is incremented
 * Used for ext4-style filesystem feature flags. This should help avoid future
   format changes. The first user is `-plaintextnames`.
* On-disk format 2

v0.3
* **Add a random 128 bit file header to authenticate file->block ownership**
 * This is an on-disk-format change
* On-disk format 1

v0.2
* Replace bash daemonization wrapper with native Go implementation
* Better user feedback on mount failures

v0.1
* First release
* On-disk format 0

See https://github.com/rfjakob/gocryptfs/tags for the release dates and associated
git tags.
