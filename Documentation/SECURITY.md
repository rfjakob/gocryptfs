GoCryptFS Security
==================

Master Key Storage
------------------

The master key is used to perform content and file name encryption.
It is stored in `gocryptfs.conf`, encrypted with AES-256-GCM using the
Key Encryption Key (KEK).

The KEK is generated from the user password using `scrypt`.

![](https://rawgit.com/rfjakob/gocryptfs/master/Documentation/master-key.svg)

File Contents
-------------

All file contents are encrypted using AES-256-GCM.

Files are segmented into 4KB blocks. Each block gets a fresh random
96 bit IV each time it is modified. A 128-bit authentication tag (GHASH)
protects each block from modifications.

Each file has a header containing a random 128-bit file ID. The
file ID and the block number are mixed into the GHASH as
*additional authenticated data*. The prevents blocks from being copied
between or within files.

![](https://rawgit.com/rfjakob/gocryptfs/master/Documentation/file-content-encryption.svg)

To support sparse files, all-zero blocks are accepted and passed through
unchanged.

File Names
----------

Every directory gets a 128-bit directory IV that is stored in each
directory as `gocryptfs.diriv`.

File names are encrypted using AES-256-CBC with the directory IV as
initialization vector. The Base64 encoding limits the usable filename length
to 176 characters.

![](https://rawgit.com/rfjakob/gocryptfs/master/Documentation/file-name-encryption.svg)
