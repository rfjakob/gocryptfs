File Format
===========

Header

	 2 bytes header version (big endian uint16, currently 2)
	16 bytes file id

Data block

	16 bytes GCM IV (nonce)
	1-4096 bytes encrypted data
	16 bytes GHASH


Example: 1-byte file
--------------------

	Header     18 bytes
	Data block 33 bytes

Total: 51 bytes


Example: 5000-byte file
-----------------------

	Header       18 bytes
	Data block 4128 bytes
	Data block  936 bytes

Total: 5082 bytes
