#!/bin/bash

if [[ -z $TMPDIR ]]; then
	TMPDIR=/var/tmp
	export TMPDIR
else
	echo "Using TMPDIR=$TMPDIR"
fi

set -eu

cd "$(dirname "$0")"
export GO111MODULE=on
MYNAME=$(basename "$0")
TESTDIR=$TMPDIR/gocryptfs-test-parent-$UID
mkdir -p "$TESTDIR"
LOCKFILE=$TESTDIR/$MYNAME.lock

unmount_leftovers() {
	RET=0
	for i in $(mount | grep "$TESTDIR" | cut -f3 -d" "); do
		echo "Warning: unmounting leftover filesystem: $i"
		tests/fuse-unmount.bash "$i"
		RET=1
	done
	return $RET
}

(
# Prevent multiple parallel test.bash instances as this causes
# all kinds of mayhem
if ! command -v flock > /dev/null ; then
	echo "flock is not available, skipping"
elif ! flock -n 200 ; then
	echo "Could not acquire lock on $LOCKFILE - already running?"
	exit 1
fi

# Clean up dangling filesystems and don't exit if we found some
unmount_leftovers || true

./build-without-openssl.bash || {
	echo "$MYNAME: build-without-openssl.bash failed"
	exit 1
}
# Don't build with openssl if we were passed "-tags without_openssl"
if [[ "$*" != *without_openssl* ]] ; then
	./build.bash
fi

if ! go tool | grep vet > /dev/null ; then
	echo "'go tool vet' not available - skipping"
elif [[ -d vendor ]] ; then
	echo "vendor directory exists, skipping 'go tool vet'"
else
	go vet "$@" ./...
fi

if command -v shellcheck > /dev/null ; then
	# SC2002 = useless cat. Does no harm, disable the check.
	shellcheck -x -e SC2002 ./*.bash
else
	echo "shellcheck not installed - skipping"
fi

#            We don't want all the subprocesses
#               holding the lock file open
#                           vvvvv
go test -count 1 ./... "$@" 200>&-
#       ^^^^^^^^
#   Disable result caching

# Clean up dangling filesystems but do exit with an error if we found one
unmount_leftovers || { echo "Error: the tests left mounted filesystems behind" ; exit 1 ; }

# The tests cannot to this themselves as they are run in parallel.
# Don't descend into possibly still mounted example filesystems.
if [[ $OSTYPE == *linux* ]] ; then
	rm -Rf --one-file-system "$TESTDIR"
else
	# MacOS "rm" does not understand "--one-file-system"
	rm -Rf "$TESTDIR"
fi

if find internal -type f -name \*.go -print0 | xargs -0 grep "panic("; then
	echo "$MYNAME: Please use log.Panic instead of naked panic!"
	exit 1
fi

# All functions from the commit msg in https://go-review.googlesource.com/c/go/+/210639
if find . -type f -name \*.go -print0 | xargs -0 grep -E 'syscall.(Setegid|Seteuid|Setgroups|Setgid|Setregid|Setreuid|Setresgid|Setresuid|Setuid)\(' ; then
	echo "$MYNAME: You probably want to use unix.Setgroups and friends. See the comments in OpenatUser() for why."
	exit 1
fi

) 200> "$LOCKFILE"
