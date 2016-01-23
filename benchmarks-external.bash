#!/bin/bash

set -eu

TIME="/usr/bin/time -f %e"

# Setup
cd /tmp
wget -q -c https://www.kernel.org/pub/linux/kernel/v3.0/linux-3.0.tar.gz
DIR1=$(mktemp -d)
DIR2=$(mktemp -d)
gocryptfs -q -init -extpass="echo test" $DIR1
gocryptfs -q -extpass="echo test" $DIR1 $DIR2
cd $DIR2
echo

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
