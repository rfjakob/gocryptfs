#!/bin/bash -eu

cd "$(dirname "$0")"

# Download /tmp/linux-3.0.tar.gz
../tests/dl-linux-tarball.bash

T=$(mktemp -d)
mkdir "$T/a" "$T/b"

set -x
../gocryptfs -init -quiet -scryptn 10 -extpass "echo test" "$@" "$T/a"
{ set +x ; } 2> /dev/null
../gocryptfs -quiet -nosyslog -extpass "echo test" "$@" "$T/a" "$T/b"

# Cleanup trap
trap "cd /; fusermount -u -z $T/b; rm -Rf $T/a" EXIT

echo "Creating 40000 empty files (linux-3.0.tar.gz contains 36782 files)..."
SECONDS=0
for dir in $(seq -w 1 200); do
	mkdir "$T/b/$dir"
	( cd "$T/b/$dir" ; touch $(seq -w 1 200) )
done
echo "done, $SECONDS seconds"

echo "Remount..."
fusermount -u "$T/b"
set -x
../gocryptfs -quiet -nosyslog -extpass "echo test" -cpuprofile "$T/cprof" -memprofile "$T/mprof" \
	"$@" "$T/a" "$T/b"
{ set +x ; } 2> /dev/null

echo "Running ls under profiler (3x)..."
for i in 1 2 3; do
SECONDS=0
ls -lR "$T/b" > /dev/null
echo "$i done, $SECONDS seconds"
done

echo
echo "Hint: go tool pprof ../gocryptfs $T/cprof"
echo "      go tool pprof -alloc_space ../gocryptfs $T/mprof"
