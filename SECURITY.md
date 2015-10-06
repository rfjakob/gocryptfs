GoCryptFS Security
==================

"Security" can be split into "Confidentiality" and "Integrity". The
security level gocryptfs provides for each is discussed in the next
sections.

Confidentiality
---------------

Confidentiality means that information cannot be extracted from the
encrypted data unless you know the key.

### File Contents

* All file contents (even the last bytes) are encrypted using AES-256-GCM
 * This is unbreakable in the foreseeable future. Attacks will focus on
   cracking the password instead (see section "Master Key Storage").
* Files are segmented into 4096 byte blocks
* Each block gets a fresh random 96 bit IV (none) each time it is written.
 * This means that identical blocks can not be identified

### File Names

* File names are encrypted using AES-256-CBC because it is robust even
  without using an IV
* The file names are padded to multiples of 16 bytes
 * This means that the exact length of the name is hidden, only length
  ranges (1-16 bytes, 17-32 bytes etc.) can be determined from the encrypted
  files
* For technical reasons, no IV is used
 * This means that files with the same name within one gocryptfs filesystem
   always get the same encrypted name

### Metadata

* The size of the file is not hidden. The exact file size can be calculated
  from the size of the encrypted file.
* File owner, file permissions and timestamps are not hidden either

Integrity
---------

Integrity means that the data cannot be modified in a meaningful way
unless you have the key. The opposite of integrity is *malleability*.

### File Contents

* The used encryption, AES-256-GCM, is a variant of
  *authenticated encryption*. Each block gets a 128 bit authentication
  tag (GMAC) appended.
 * This means that any modification inside a block will be detected when reading
   the block and decryption will be aborted. The failure is logged and an
   I/O error is returned to the user.
* Each block uses its block number as GCM *authentication data*
 * This means the position of the blocks is protected as well. The blocks
   can not be reordered without causing an decryption error.
* However, proper affiliation of a block to the file is can not be verified.
 * This means that blocks can be copied between different files provided
   that they stay at the same position. 
* For technical reasons (sparse files), the special "all-zero" block is
  always seen as a valid block that decrypts to all-zero plaintext.
 * This means that whole blocks can be zeroed out

### File Names

* File names are only weakly protected against modifications.
 * Changing a single byte causes a decode error in most of the
   cases. The failure is logged and the file is no longer visible in the
   directory.
 * If no decode error is triggered, at least 16 bytes of the filename will
   be corrupted (randomized).
* However, file names can always be truncated to multiples of 16 bytes.

### Metadata

* The file size is not protected against modifications
 * However, the block integrity protection limits modifications to block
   size granularity.
 * This means that files can be truncated to multiples of 4096 bytes.
* Ownership, timestamp and permissions are not protected and can be changed
  as usual.

Master Key Storage
------------------

The *master key* is used to perform content and file name encryption.
It is stored in `gocryptfs.conf`, encrypted with AES-256-GCM using the
*unlock key*.

The unlock key is generated from a user password using `scrypt`.
A successful decryption of the master key means that the GMAC authentication
passed and the password is correct. The master key is then used to
mount the filesystem.
