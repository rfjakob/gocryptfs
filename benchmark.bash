#!/bin/bash

# Run the set of "canonical" benchmarks that are shown on
# https://nuetzlich.net/gocryptfs/comparison/

set -eu

TIME="/usr/bin/time -f %e"

# Setup
cd /tmp
wget -nv --show-progress -c https://www.kernel.org/pub/linux/kernel/v3.0/linux-3.0.tar.gz
DIR1=$(mktemp -d)
DIR2=$(mktemp -d)

if [ $# -eq 1 ] && [ "$1" == "-encfs" ]; then
	echo "Testing EncFS"
	encfs --extpass="echo test" --standard $DIR1 $DIR2 > /dev/null
else
	gocryptfs -q -init -extpass="echo test" -scryptn=10 $DIR1
	gocryptfs -q -extpass="echo test" $DIR1 $DIR2
fi
cd $DIR2

# Benchmarks
echo -n "WRITE: "
dd if=/dev/zero of=zero bs=128K count=1000 2>&1 | tail -n 1
rm zero
sleep 1
echo -n "UNTAR: "
$TIME tar xzf ../linux-3.0.tar.gz
sleep 1
echo -n "LS:    "
$TIME ls -lR linux-3.0 > /dev/null
sleep 1
echo -n "RM:    "
$TIME rm -Rf linux-3.0

# Cleanup
cd ..
fusermount -u $DIR2 -z
rm -Rf $DIR1 $DIR2
