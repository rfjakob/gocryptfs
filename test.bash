#!/bin/bash

set -eu

cd "$(dirname "$0")"
MYNAME=$(basename "$0")
TESTDIR=/tmp/gocryptfs-test-parent
LOCKFILE=$TESTDIR/$MYNAME.lock

mkdir -p $TESTDIR

(
# Prevent multiple parallel test.bash instances as this causes
# all kinds of mayham
if ! flock -n 200 ; then
	echo "Could not acquire lock on $LOCKFILE - already running?"
	exit 1
fi

# Clean up dangling filesystems
source tests/fuse-unmount.bash
for i in $(mount | grep $TESTDIR | cut -f3 -d" "); do
	echo "Warning: unmounting leftover filesystem: $i"
	fuse-unmount $i
done

./build-without-openssl.bash
# Building with openssl is difficult on OSX, so only do it on Linux.
if [[ $OSTYPE == linux* ]] ; then
	./build.bash
fi

if go tool | grep vet > /dev/null ; then
	go tool vet -all -shadow .
else
	echo "'go tool vet' not available - skipping"
fi

# We don't want all the subprocesses holding the lock file open
go test ./... $* 200>&-

# The tests cannot to this themselves as they are run in parallel.
# Don't descend into possibly still mounted example filesystems.
rm -Rf --one-file-system $TESTDIR

if grep -R "panic(" internal ; then
	echo "Please use log.Panic instead of naked panic!"
	exit 1
fi

) 200> $LOCKFILE
