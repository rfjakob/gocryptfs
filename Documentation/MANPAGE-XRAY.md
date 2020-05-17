% GOCRYPTFS-XRAY(1)
% github.com/rfjakob
% Jan 2018

NAME
====

gocryptfs-xray - examine gocryptfs-related data

SYNOPSIS
========

#### Examine encrypted file/directory
gocryptfs-xray CIPHERDIR/ENCRYPTED-FILE-OR-DIR

#### Decrypt and show master key
gocryptfs-xray -dumpmasterkey CIPHERDIR/gocryptfs.conf

#### Encrypt paths
gocryptfs-xray -encrypt-paths SOCKET

DESCRIPTION
===========

Available options are listed below.

#### -0
Use \\0 instead of \\n as separator for -decrypt-paths and -encrypt-paths.

#### -aessiv
Assume AES-SIV mode instead of AES-GCM when examining an encrypted file.
Is not needed and has no effect in `-dumpmasterkey` mode.

#### -decrypt-paths
Decrypt file paths using gocryptfs control socket. Reads from stdin.
See `-ctlsock` in gocryptfs(1).

#### -dumpmasterkey
Decrypts and shows the master key.

#### -encrypt-paths
Encrypt file paths using gocryptfs control socket. Reads from stdin.
See `-ctlsock` in gocryptfs(1).

EXAMPLES
========

Examine an encrypted file:

	gocryptfs-xray myfs/mCXnISiv7nEmyc0glGuhTQ

Print the master key:

	gocryptfs-xray -dumpmasterkey myfs/gocryptfs.conf

Mount gocryptfs with control socket and use gocryptfs-xray to
encrypt some paths:

    gocryptfs -ctlsock myfs.sock myfs myfs.mnt
    echo -e "foo\nbar" | gocryptfs-xray -encrypt-paths myfs.sock

SEE ALSO
========
gocryptfs(1) fuse(8)
