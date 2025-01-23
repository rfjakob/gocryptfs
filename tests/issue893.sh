#!/bin/bash
# Reproducer for https://github.com/rfjakob/gocryptfs/issues/893 .
# Run this script as non-root against a root-mounted gocryptfs -allow_other.

set -eu

mountpoint $1
cd $1

work() {
	for i in $(seq 100) ; do
		D=mtest.$BASHPID.$i/foo/bar/baz
		mkdir -p $D
		touch $D/foo $D/bar
		echo AAAAAAAAAAAAAAAAAAAAA > $D/foo
		rm $D/foo
		mkdir $D/baz
	done
}

rm -Rf mtest.*
echo .

work &
work &

wait
