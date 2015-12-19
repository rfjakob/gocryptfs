% GOCRYPTFS(1)
% github.com/rfjakob
% Nov 2015

NAME
====

gocryptfs - mount an encrypted directory

SYNOPSIS
========

Initialize encrypted filesystem
-------------------------------

gocryptfs -init [OPTIONS] CIPHERDIR

Mount
-----

gocryptfs [OPTIONS] CIPHERDIR MOUNTPOINT

Change password
---------------

gocryptfs -passwd [OPTIONS] CIPHERDIR

DESCRIPTION
===========

Options:

**-config string**
:	Use specified config file instead of CIPHERDIR/gocryptfs.conf

**-cpuprofile string**
:	Write cpu profile to specified file

**-debug**
:	Enable debug output

**-diriv**
:	Use per-directory file name IV (default true)

**-emenames**
:	Use EME filename encryption (default true). This option implies diriv.

**-extpass string**
:	Use an external program (like ssh-askpass) for the password prompt.
The program should return the password on stdout, a trailing newline is
stripped by gocryptfs. Using something like "cat /mypassword.txt" allows
to mount the gocryptfs filesytem without user interaction.

**-f**
:	Stay in the foreground instead of forking away.

**-fusedebug**
:	Enable fuse library debug output

**-gcmiv128**
:	Use an 128-bit IV for GCM encryption instead of Go's default of
96 bits (default true). This pushes back the birthday bound for IV
collisions far enough to make it irrelevant.

**-init**
:	Initialize encrypted directory

**-masterkey string**
:	Mount with explicit master key specified on the command line. This
option can be used to mount a gocryptfs filesystem without a config file.
Note that the command line, and with it the master key, is visible to
anybody on the machine who can execute "ps -auxwww".

**-notifypid int**
:	Send USR1 to the specified process after successful mount. This is
used internally for daemonization.

**-openssl bool**
:	Use OpenSSL instead of built-in Go crypto (default true). Using
built-in crypto is 4x slower.

**-passwd**
:	Change password

**-plaintextnames**
:	Do not encrypt file names

**-q**
:	Quiet - silence informational messages

**-scryptn int**
:	scrypt cost parameter logN. Setting this to a lower value speeds up
mounting but makes the password susceptible to brute-force attacks (default 16)

**-version**
:	Print version and exit

**-zerokey**
:	Use all-zero dummy master key. This options is only intended for
automated testing as it does not provide any security.

