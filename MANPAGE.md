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

**-extpass string**
:	Use an external program (like ssh-askpass) for the password prompt.
The program should return the password on stdout, a trailing newline is
stripped by gocryptfs.

**-f**
:	Stay in the foreground

**-fusedebug**
:	Enable fuse library debug output

**-init**
:	Initialize encrypted directory

**-masterkey string**
:	Mount with explicit master key

**-notifypid int**
:	Send USR1 to the specified process after successful mount - used internally for daemonization

**-openssl bool**
:	Use OpenSSL instead of built-in Go crypto (default true)

**-passwd**
:	Change password

**-plaintextnames**
:	Do not encrypt file names

**-q**
:	Quiet - silence informational messages

**-version**
:	Print version and exit

**-zerokey**
:	Use all-zero dummy master key

