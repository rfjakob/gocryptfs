[![gocryptfs](https://nuetzlich.net/gocryptfs/img/gocryptfs-logo.paths-black.svg)](https://nuetzlich.net/gocryptfs/) [![Build Status](https://travis-ci.org/rfjakob/gocryptfs.svg?branch=master)](https://travis-ci.org/rfjakob/gocryptfs) ![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
==============
An encrypted overlay filesystem written in Go.
Official website: https://nuetzlich.net/gocryptfs

gocryptfs is built on top the excellent
[go-fuse](https://github.com/hanwen/go-fuse) FUSE library and its
LoopbackFileSystem API.

This project was inspired by EncFS and strives to fix its security
issues while providing good performance.
For details on the security of gocryptfs see the
[Security](https://nuetzlich.net/gocryptfs/security/) design document.

All tags from v0.4 onward are signed by the *gocryptfs signing key*.
Please check [Signed Releases](https://nuetzlich.net/gocryptfs/releases/) for
details.

Current Status
--------------

gocryptfs is a young project. While bugs in any software can cause issues,
bugs in encryption software can cause catastrophic data loss. Keep a backup
of your gocryptfs filesystem *and* store a copy of your master key (printed
on mount) in a safe place.

Only Linux is supported at the moment. [Help wanted for a Mac OS X port.](https://github.com/rfjakob/gocryptfs/issues/15)

Testing
-------

gocryptfs comes with is own test suite that is constantly expanded as features are
added. Run it using `./test.bash`. It takes about 1 minute and requires FUSE
as it mounts several test filesystems.

In addition, I have ported `xfstests` to FUSE, the result is the
[fuse-xfstests](https://github.com/rfjakob/fuse-xfstests) project. gocryptfs
passes the "generic" tests with one exception, results:  [XFSTESTS.md](Documentation/XFSTESTS.md)

A lot of work has gone into this. The testing has found bugs in gocryptfs
as well as in go-fuse.

The one exception is generic/035, see [go-fuse issue 55](https://github.com/hanwen/go-fuse/issues/55)
for details. While this is a POSIX violation, I do not see any real-world impact.

Compile
-------

	$ go get github.com/rfjakob/gocryptfs

Use
---

	$ mkdir cipher plain
	$ $GOPATH/bin/gocryptfs -init cipher
	$ $GOPATH/bin/gocryptfs cipher plain

See the [Quickstart](https://nuetzlich.net/gocryptfs/quickstart/) page for more info.

The [MANPAGE.md](Documentation/MANPAGE.md) containes a description of available command-line options.
If you already have gocryptfs installed, run `./MANPAGE-render.bash` to bring up the rendered manpage in
your man pager (requires pandoc).

Storage Overhead
----------------

* Empty files take 0 bytes on disk
* 18 byte file header for non-empty files (2 bytes version, 16 bytes random file id)
* 28 bytes of storage overhead per 4kB block (12 byte nonce, 16 bytes auth tag)

[file-format.md](Documentation/file-format.md) contains a more detailed description.

Performance
-----------

gocryptfs uses openssl through
[spacemonkeygo/openssl](https://github.com/spacemonkeygo/openssl)
for a 3x speedup compared to Go's builtin AES-GCM implementation (see
[go-vs-openssl.md](openssl_benchmark/go-vs-openssl.md) for details).

Run `./benchmark.bash` to run the benchmarks.

The output should look like this:

```
$ ./benchmark.bash
linux-3.0.tar.gz       100%[===========================>]  92,20M  2,96MB/s    in 35s
2016-01-23 20:08:11 URL:https://www.kernel.org/pub/linux/kernel/v3.0/linux-3.0.tar.gz [...]
WRITE: 131072000 bytes (131 MB) copied, 1,36225 s, 96,2 MB/s
UNTAR: 23.16
LS:    1.71
RM:    4.36
```

Changelog
---------

v0.8
* Redirect output to syslog when running in the background
* New command-line option:
 * `-memprofile`: Write a memory allocation debugging profile the specified
   file

v0.7.2
* **Fix performance issue in small file creation**
 * This brings performance on-par with EncFS paranoia mode, with streaming writes
   significantly faster
 * The actual [fix](https://github.com/hanwen/go-fuse/commit/c4b6b7949716d13eec856baffc7b7941ae21778c)
   is in the go-fuse library. There are no code changes in gocryptfs.

v0.7.1
* Make the `build.bash` script compatible with Go 1.3
* Disable fallocate on OSX (system call not availabe)
* Introduce pre-built binaries for Fedora 23 and Debian 8

v0.7
* **Extend GCM IV size to 128 bit from Go's default of 96 bit**
 * This pushes back the birthday bound to make IV collisions virtually
   impossible
 * This is a forwards-compatible change. gocryptfs v0.7 can mount filesystems
   created by earlier versions but not the other way round.
* New command-line option:
 * `-gcmiv128`: Use 128-bit GCM IVs (default true)

v0.6
* **Wide-block filename encryption using EME + DirIV**
 * EME (ECB-Mix-ECB) provides even better security than CBC as it fixes
   the prefix leak. The used Go EME implementation is
   https://github.com/rfjakob/eme which is, as far as I know, the first
   implementation of EME in Go.
 * This is a forwards-compatible change. gocryptfs v0.6 can mount filesystems
   created by earlier versions but not the other way round.
* New command-line option:
 * `-emenames`: Enable EME filename encryption (default true)

v0.5.1
* Fix a rename regression caused by DirIV and add test case
* Use fallocate to guard against out-of-space errors

v0.5
* **Stronger filename encryption: DirIV**
 * Each directory gets a random 128 bit file name IV on creation,
   stored in `gocryptfs.diriv`
 * This makes it impossible to identify identically-named files across
   directories
 * A single-entry IV cache brings the performance cost of DirIV close to
   zero for common operations (see performance.txt)
 * This is a forwards-compatible change. gocryptfs v0.5 can mount filesystems
   created by earlier versions but not the other way round.
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
