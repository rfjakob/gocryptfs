#!/bin/bash -eu

# Run the set of "canonical" benchmarks that are shown on
# https://nuetzlich.net/gocryptfs/comparison/

cd "$(dirname "$0")"

# Setup
CRYPT=$(mktemp -d /tmp/benchmark.bash.XXX)
MNT=$CRYPT.mnt
mkdir $MNT

# Mount
if [ $# -eq 1 ] && [ "$1" == "-encfs" ]; then
	echo "Testing EncFS at $MNT"
	encfs --extpass="echo test" --standard $CRYPT $MNT > /dev/null
else
	echo "Testing gocryptfs at $MNT"
	gocryptfs -q -init -extpass="echo test" -scryptn=10 $CRYPT
	gocryptfs -q -extpass="echo test" $CRYPT $MNT
fi

# Cleanup trap
trap "cd /; fusermount -u -z $MNT; rm -rf $CRYPT $MNT" EXIT

# Benchmarks
./tests/canonical-benchmarks.bash $MNT

