% GOCRYPTFS-XRAY(1)
% github.com/rfjakob
% Jan 2018

NAME
====

gocryptfs-xray - examine gocryptfs-related data

SYNOPSIS
========

#### Examine encrypted file/directory
gocryptfs CIPHERDIR/ENCRYPTED-FILE-OR-DIR

#### Decrypt and show master key
gocryptfs -dumpmasterkey CIPHERDIR/gocryptfs.conf

DESCRIPTION
===========

Available options are listed below.

#### -dumpmasterkey
Decrypts and shows the master key.

EXAMPLES
========

Examine an encrypted file:

	gocryptfs-xray myfs/mCXnISiv7nEmyc0glGuhTQ

Print the master key:

	gocryptfs-xray -dumpmasterkey myfs/gocryptfs.conf

SEE ALSO
========
gocryptfs(1) fuse(8)
