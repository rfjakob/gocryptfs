#!/bin/bash

set -eu

cleanup() {
	cd "$LOCAL_TMP"
	fusermount -u gocryptfs.mnt
	rm -Rf "$SSHFS_TMP"
	fusermount -u sshfs.mnt
	cd /
	rm -Rf "$LOCAL_TMP"
}

prepare_mounts() {
	LOCAL_TMP=$(mktemp -d -t "$MYNAME.XXX")
	cd "$LOCAL_TMP"
	echo "working directory: $PWD"
	mkdir sshfs.mnt gocryptfs.mnt
	sshfs "$HOST:/tmp" sshfs.mnt
	echo "sshfs mounted: $HOST:/tmp -> sshfs.mnt"
	trap cleanup EXIT
	SSHFS_TMP=$(mktemp -d "sshfs.mnt/$MYNAME.XXX")
	mkdir "$SSHFS_TMP/gocryptfs.crypt"
	gocryptfs -q -init -extpass "echo test" -scryptn=10 "$SSHFS_TMP/gocryptfs.crypt"
	gocryptfs -q -extpass "echo test" "$SSHFS_TMP/gocryptfs.crypt" gocryptfs.mnt
	echo "gocryptfs mounted: $SSHFS_TMP/gocryptfs.crypt -> gocryptfs.mnt"
}

etime() {
	T=$(/usr/bin/time -f %e -o /dev/stdout "$@")
	LC_ALL=C printf %20.2f "$T"
}

MYNAME=$(basename "$0")
HOST=$1

prepare_mounts

echo
echo "$MYNAME:    sshfs  gocryptfs-on-sshfs"
echo -n "git init  "
etime git init -q "$SSHFS_TMP/git1"
etime git init -q gocryptfs.mnt/git1
echo

git init -q git2
echo -n "rsync     "
etime rsync -a --no-group git2 "$SSHFS_TMP"
etime rsync -a --no-group git2 gocryptfs.mnt
echo

echo -n "rm -R     "
etime rm -R "$SSHFS_TMP/git1" "$SSHFS_TMP/git2"
etime rm -R gocryptfs.mnt/git1 gocryptfs.mnt/git2
echo

echo -n "mkdir     "
pushd "$SSHFS_TMP" > /dev/null
etime mkdir $(seq 1 20)
popd > /dev/null
cd gocryptfs.mnt
etime mkdir $(seq 1 20)
cd ..
echo

echo -n "rmdir     "
pushd "$SSHFS_TMP" > /dev/null
etime rmdir $(seq 1 20)
popd > /dev/null
cd gocryptfs.mnt
etime rmdir $(seq 1 20)
cd ..
echo

echo -n "touch     "
pushd "$SSHFS_TMP" > /dev/null
etime touch $(seq 101 120)
popd > /dev/null
cd gocryptfs.mnt
etime touch $(seq 101 120)
cd ..
echo

echo -n "rm        "
pushd "$SSHFS_TMP" > /dev/null
etime rm $(seq 101 120)
popd > /dev/null
cd gocryptfs.mnt
etime rm $(seq 101 120)
cd ..
echo
