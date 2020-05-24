#!/bin/bash

set -eu

function cleanup {
	fusermount -u -z gocryptfs.mnt || true
	rm -Rf "$SSHFS_TMP"
	fusermount -u -z sshfs.mnt
	cd /
	rm -Rf "$LOCAL_TMP"
}

function prepare_mounts {
	LOCAL_TMP=$(mktemp -d -t "$MYNAME.XXX")
	cd $LOCAL_TMP
	echo "working directory: $PWD"
	mkdir sshfs.mnt gocryptfs.mnt
	sshfs $HOST:/tmp sshfs.mnt
	echo "sshfs mounted: $HOST:/tmp -> sshfs.mnt"
	trap cleanup EXIT
	SSHFS_TMP=$(mktemp -d "sshfs.mnt/$MYNAME.XXX")
	mkdir $SSHFS_TMP/gocryptfs.crypt
	gocryptfs -q -init -extpass "echo test" -scryptn=10 $SSHFS_TMP/gocryptfs.crypt
	gocryptfs -q -extpass "echo test" $SSHFS_TMP/gocryptfs.crypt gocryptfs.mnt
	echo "gocryptfs mounted: $SSHFS_TMP/gocryptfs.crypt -> gocryptfs.mnt"
}

function etime {
	T=$(/usr/bin/time -f %e -o /dev/stdout "$@")
	printf %20.2f "$T"
}

MYNAME=$(basename "$0")
HOST=$1

prepare_mounts

# Make the bash builtin "time" print out only the elapsed wall clock
# seconds
TIMEFORMAT=%R

echo
echo "$MYNAME:    sshfs  gocryptfs-on-sshfs"
echo -n "git init  "
etime git init -q sshfs.mnt/git1
etime git init -q gocryptfs.mnt/git1
echo

git init -q git2
echo -n "rsync     "
etime rsync -a --no-group git2 sshfs.mnt
etime rsync -a --no-group git2 gocryptfs.mnt
echo
