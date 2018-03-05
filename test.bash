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
if ! command -v flock > /dev/null ; then
	echo "flock is not available, skipping"
elif ! flock -n 200 ; then
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
# Don't build with openssl if we were passed "-tags without_openssl"
if [[ "$@" != *without_openssl* ]] ; then
	./build.bash
fi

if ! go tool | grep vet > /dev/null ; then
	echo "'go tool vet' not available - skipping"
elif [[ -d vendor ]] ; then
	echo "vendor directory exists, skipping 'go tool vet'"
else
	go tool vet -all -shadow .
fi

#            We don't want all the subprocesses
#               holding the lock file open
#                         vvvvv
go test -count 1 ./... "$@" 200>&-
#       ^^^^^^^^
#   Disable result caching

# The tests cannot to this themselves as they are run in parallel.
# Don't descend into possibly still mounted example filesystems.
if [[ $OSTYPE == *linux* ]] ; then
	rm -Rf --one-file-system $TESTDIR
else
	# MacOS "rm" does not understand "--one-file-system"
	rm -Rf $TESTDIR
fi

if grep -R "panic(" internal ; then
	echo "Please use log.Panic instead of naked panic!"
	exit 1
fi

) 200> $LOCKFILE
