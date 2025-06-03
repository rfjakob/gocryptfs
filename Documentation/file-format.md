File Format
===========

Empty files are stored as empty files.

Non-empty files contain a *Header* and one or more *Data blocks*.

Header
------

	 2 bytes header version (big endian uint16, currently 2)
	16 bytes file id

Data block, default AES-GCM mode
--------------------------------

	16 bytes GCM IV (nonce)
	1-4096 bytes encrypted data
	16 bytes GHASH

Overhead = (16+16)/4096 = 1/128 = 0.78125 %

Data block, AES-SIV mode
------------------------

AES-SIV is used in reverse mode, or when explicitly enabled with `-init -aessiv`.

	16 bytes nonce
	16 bytes SIV
	1-4096 bytes encrypted data

Overhead = (16+16)/4096 = 1/128 = 0.78125 %

Data block, XChaCha20-Poly1305
------------------------------

Enabled via `-init -xchacha`

	24 bytes nonce
	1-4096 bytes encrypted data
	16 bytes Poly1305 tag

Overhead = (24+16)/4096 = 0.98 %

Examples
========

0-byte file (all modes)
-----------------------

	(empty)

Total: 0 bytes

1-byte file, AES-GCM and AES-SIV mode
-------------------------------------

	Header     18 bytes
	Data block 33 bytes

Total: 51 bytes

5000-byte file, , AES-GCM and AES-SIV mode
------------------------------------------

	Header       18 bytes
	Data block 4128 bytes
	Data block  936 bytes

Total: 5082 bytes

1-byte file, XChaCha20-Poly1305 mode
------------------------------------

	Header     18 bytes
	Data block 41 bytes

Total: 59 bytes

5000-byte file, XChaCha20-Poly1305 mode
---------------------------------------

	Header       18 bytes
	Data block 4136 bytes
	Data block  944 bytes

Total: 5098 bytes

See Also
========

https://nuetzlich.net/gocryptfs/forward_mode_crypto/ / https://github.com/rfjakob/gocryptfs-website/blob/master/docs/forward_mode_crypto.md
