GoCryptFS
=========
An encrypted overlay filesystem focused on security and correctness.

gocryptfs is built on top the excellent
[go-fuse](https://github.com/hanwen/go-fuse) FUSE library and its
LoopbackFileSystem API.

This project was inspired by [EncFS](https://github.com/vgough/encfs)
and strives to fix its security issues (see EncFS tickets 9, 13, 14, 16).

"Security" can be split into "Confidentiality" and "Integrity". The
security level gocryptfs provides for each is discussed in the next
sections.

Confidentiality
---------------

Confidentiality means that information cannot be extracted from the
encrypted data unless you know the key.

### File Contents

* File contents are encrypted using AES-128-GCM
* Files are segmented into 4096 byte blocks
* Each block gets a fresh random 96 bit IV (none) each time it is written.
 * This means that identical blocks can not be identified
* The size of the file is not hidden. The exact file size can be calculated
  from the size of the encrypted file.

### File Names

* File names are encrypted using AES-128-CBC because it is robust even
  without using an IV
* The file names are padded to multiples of 16 bytes
 * This means that the exact length of the name is hidden, only length
  ranges (1-16 bytes, 17-32 bytes etc.) can be determined from the encrypted
  files
* For technical reasons, no IV is used
 * This means that files with the same name within one gocryptfs filesystem
   always get the same encrypted name

Integrity
---------

Integrity means that the data cannot be modified in a meaningful way
unless you have the key. The opposite of integrity is *malleability*.

### File Contents

* The used encryption, AES-128-GCM, is a variant of
  *authenticated encryption*. Each block gets a 128 bit authentication
  tag (GMAC) appended.
 * This means that any modification inside block will be detected when reading
   the block and decryption will be aborted. The failure is logged and an
   I/O error is returned to the user.
* However, blocks can be copied around in the encrypted data.
  The block authentication tag only protects each individual block. It
  does not protect the ordering of blocks.
* For technical reasons (file holes), the special "all-zero" block is
  seen as a valid block that decrypts to an all-zero block.

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
Run `./benchmark.bash` to run the test suite and the streaming read/write
benchmark.

The output should look like this:

	$ ./benchmark.bash
	[...]
	BenchmarkStreamWrite	     100	  11816665 ns/op	  88.74 MB/s
	BenchmarkStreamRead 	     200	   7848155 ns/op	 133.61 MB/s
	ok  	github.com/rfjakob/gocryptfs	9.407s

