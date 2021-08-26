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

Data block, XChaCha20-Poly1305 (enabled via `-init -xchacha`)

	24 bytes nonce
	1-4096 bytes encrypted data
	16 bytes Poly1305 tag

Full block overhead (AES-GCM and AES-SIV mode) = 32/4096 = 1/128 = 0.78125 %

Full block overhead (XChaCha20-Poly1305 mode) = 40/4096 = \~1 %

Example: 1-byte file, AES-GCM and AES-SIV mode
----------------------------------------------

	Header     18 bytes
	Data block 33 bytes

Total: 51 bytes

Example: 5000-byte file, , AES-GCM and AES-SIV mode
---------------------------------------------------

	Header       18 bytes
	Data block 4128 bytes
	Data block  936 bytes

Total: 5082 bytes

Example: 1-byte file, XChaCha20-Poly1305 mode
----------------------------------------------

	Header     18 bytes
	Data block 41 bytes

Total: 59 bytes

Example: 5000-byte file, XChaCha20-Poly1305 mode
----------------------------------------------

	Header       18 bytes
	Data block 4136 bytes
	Data block  944 bytes

Total: 5098 bytes
