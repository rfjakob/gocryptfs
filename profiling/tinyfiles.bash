#!/bin/bash -eu
#
# Create a tarball of 100k 1-byte files using reverse mode
# https://github.com/rfjakob/gocryptfs/issues/965

cd "$(dirname "$0")"

T=$(mktemp -d)
mkdir "$T/a" "$T/b"

../gocryptfs -init -reverse -quiet -scryptn 10 -extpass "echo test" "$@" "$T/a"

# Cleanup trap
# shellcheck disable=SC2064
trap "cd /; fusermount -u -z '$T/b'; rm -Rf '$T/a'" EXIT

echo "Creating 100k 1-byte files"
SECONDS=0
dd if=/dev/urandom bs=100k count=1 status=none | split --suffix-length=10 -b 1 - "$T/a/tinyfile."
echo "done, $SECONDS seconds"

../gocryptfs -reverse -quiet -nosyslog -extpass "echo test" \
 -cpuprofile "$T/cprof" -memprofile "$T/mprof" \
 "$@" "$T/a" "$T/b"

echo "Running tar under profiler..."
SECONDS=0
tar -cf /dev/null "$T/b"
echo "done, $SECONDS seconds"

echo
echo "Hint: go tool pprof ../gocryptfs $T/cprof"
echo "      go tool pprof -alloc_space ../gocryptfs $T/mprof"
