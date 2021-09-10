#!/bin/bash -eu

cd "$(dirname "$0")"

# Download /tmp/linux-3.0.tar.gz
../tests/dl-linux-tarball.bash

T=$(mktemp -d)
mkdir "$T/a" "$T/b"

set -x
../gocryptfs -init -quiet -scryptn 10 -extpass "echo test" "$@" "$T/a"
../gocryptfs -quiet -extpass "echo test" -cpuprofile "$T/cprof" -memprofile "$T/mprof" \
	"$@" "$T/a" "$T/b"
{ set +x ; } 2> /dev/null

# Cleanup trap
trap "cd /; fusermount -u -z $T/b; rm -Rf $T/a" EXIT

echo "Extracting..."
time tar xzf /tmp/linux-3.0.tar.gz -C "$T/b"

echo
echo "Hint: go tool pprof ../gocryptfs $T/cprof"
echo "      go tool pprof -alloc_space ../gocryptfs $T/mprof"
