#!/bin/bash

set -eu

# Setup
cd /tmp
wget -nv --show-progress -c https://www.kernel.org/pub/linux/kernel/v3.0/linux-3.0.tar.gz
DIR1=$(mktemp -d)
DIR2=$(mktemp -d)
gocryptfs -q -init -extpass="echo test" $DIR1
gocryptfs -q -extpass="echo test" -nosyslog $DIR1 $DIR2
cd $DIR2

# Cleanup trap
# Note: gocryptfs may have already umounted itself because bash relays SIGINT
# Just ignore fusermount errors.
trap "cd /; fusermount -u -z $DIR2; rm -rf $DIR1 $DIR2" EXIT

# Loop
N=1
while true
do
	echo -n "$N "
	echo -n "extract "
	tar xf /tmp/linux-3.0.tar.gz
	echo -n "diff "
	diff -ur linux-3.0 /tmp/linux-3.0
	echo -n "rm "
	rm -Rf linux-3.0
	date
	let N=$N+1
done
