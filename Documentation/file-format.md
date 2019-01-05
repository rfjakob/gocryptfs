File Format
===========

Header

	 2 bytes header version (big endian uint16, currently 2)
	16 bytes file id

Data block, default AES-GCM mode

	16 bytes GCM IV (nonce)
	1-4096 bytes encrypted data
	16 bytes GHASH

Data block, AES-SIV mode (used in reverse mode, or when explicitly enabled with `-init -aessiv`)

	16 bytes nonce
	16 bytes SIV
	1-4096 bytes encrypted data

Full block overhead = 32/4096 = 1/128 = 0.78125 %

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
