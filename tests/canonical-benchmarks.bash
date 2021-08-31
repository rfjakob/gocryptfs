#!/bin/bash -eu
#
# Run the set of "canonical" benchmarks that are shown on
# https://nuetzlich.net/gocryptfs/comparison/
# against the directory passed as "$1".
#
# This is called by the top-level script "benchmark.bash".


MYNAME=$(basename "$0")

if [ $# -ne 1 ]; then
	echo "usage: $MYNAME TESTDIR"
	exit 1
fi

# Resolve possible relative TESTDIR path before cd'ing away
TESTDIR=$(realpath "$1")

# Download /tmp/linux-3.0.tar.gz
cd "$(dirname "$0")"
MD5="$PWD/stress_tests/linux-3.0.md5sums"
./dl-linux-tarball.bash

# cd to TESTDIR
cd "$TESTDIR"

# Execute command, discard all stdout output, print elapsed time
# (to stderr, unfortunately).
function etime {
	# Make the bash builtin "time" print out only the elapsed wall clock
	# seconds
	TIMEFORMAT=%R
	time "$@" > /dev/null
}

echo -n "WRITE: "
dd if=/dev/zero of=zero bs=131072 count=2000 2>&1 | tail -n 1
sleep 0.1
echo -n "READ:  "
dd if=zero of=/dev/null bs=131072 count=2000 2>&1 | tail -n 1
rm zero
sleep 0.1
echo -n "UNTAR: "
etime tar xzf /tmp/linux-3.0.tar.gz
sleep 0.1
echo -n "MD5:   "
etime md5sum --quiet -c "$MD5"
sleep 0.1
echo -n "LS:    "
etime ls -lR linux-3.0
sleep 0.1
echo -n "RM:    "
etime rm -Rf linux-3.0
