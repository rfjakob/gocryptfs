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

**-d, -debug**
:	Enable debug output

**-diriv**
:	Use per-directory file name IV (default true)
This flag is useful when recovering old gocryptfs filesystems using
"-masterkey". It is ignored (stays at the default) otherwise.

**-emenames**
:	Use EME filename encryption (default true), implies diriv.
This flag is useful when recovering old gocryptfs filesystems using
"-masterkey". It is ignored (stays at the default) otherwise.

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
This flag is useful when recovering old gocryptfs filesystems using
"-masterkey". It is ignored (stays at the default) otherwise.

**-init**
:	Initialize encrypted directory

**-longnames**
:	Store names longer than 176 bytes in extra files (default true)
This flag is useful when recovering old gocryptfs filesystems using
"-masterkey". It is ignored (stays at the default) otherwise.

**-masterkey string**
:	Mount with explicit master key specified on the command line. This
option can be used to mount a gocryptfs filesystem without a config file.
Note that the command line, and with it the master key, is visible to
anybody on the machine who can execute "ps -auxwww".

**-memprofile string**
:	Write memory profile to specified file. This is useful when debugging
memory usage of gocryptfs.

**-nosyslog**
:	Diagnostic messages are normally redirected to syslog once gocryptfs
daemonizes. This option disables the redirection and messages will
continue be printed to stdout and stderr.

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

**-q, -quiet**
:	Quiet - silence informational messages

**-scryptn int**
:	scrypt cost parameter logN. Setting this to a lower value speeds up
mounting but makes the password susceptible to brute-force attacks (default 16)

**-version**
:	Print version and exit

**-wpanic**
:	When encountering a warning, panic and exit immediately. This is
useful in regression testing.

**-zerokey**
:	Use all-zero dummy master key. This options is only intended for
automated testing as it does not provide any security.


EXAMPLES
========

Create and mount an encrypted filesystem:

mkdir /tmp/g1 /tmp/g2

gocryptfs -init /tmp/g1  
gocryptfs /tmp/g1 /tmp/g2

