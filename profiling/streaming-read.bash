#!/bin/bash -eu

cd "$(dirname "$0")"

T=$(mktemp -d)
mkdir "$T/a" "$T/b"

set -x
../gocryptfs -init -quiet -scryptn 10 -extpass "echo test" "$@" "$T/a"
{ set +x ; } 2> /dev/null
../gocryptfs -quiet -extpass "echo test" "$@" "$T/a" "$T/b"

# Cleanup trap
trap "cd /; fusermount -u -z $T/b; rm -Rf $T/a" EXIT

# Write 100MB test file
dd if=/dev/zero of="$T/b/zero" bs=1M count=100 status=none

# Remount with profiling
fusermount -u "$T/b"
set -x
../gocryptfs -quiet -extpass "echo test" -cpuprofile "$T/cprof" -memprofile "$T/mprof" \
	 "$@" "$T/a" "$T/b"
{ set +x ; } 2> /dev/null

# Read 10 x 100MB instead of 1 x 1GB to keep the used disk space low
for i in $(seq 1 10); do
	dd if="$T/b/zero" of=/dev/null bs=1M count=100
done

echo
echo "Hint: go tool pprof ../gocryptfs $T/cprof"
echo "      go tool pprof -alloc_space ../gocryptfs $T/mprof"
