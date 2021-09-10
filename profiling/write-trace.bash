#!/bin/bash -eu
#
# Write an execution trace of writing 100MB of data
# to a new gocryptfs mount on /tmp

cd "$(dirname "$0")"

T=$(mktemp -d)
mkdir "$T/a" "$T/b"

set -x
../gocryptfs -init -quiet -scryptn 10 -extpass "echo test" "$@" "$T/a"
../gocryptfs -quiet -extpass "echo test" -trace "$T/trace" \
	"$@" "$T/a" "$T/b"
{ set +x ; } 2> /dev/null

# Cleanup trap
trap "cd /; fusermount -u -z $T/b; rm -Rf $T/a" EXIT

# Write only 1x100MB, otherwise the trace gets too big.
dd if=/dev/zero of="$T/b/zero" bs=1M count=100

echo
echo "Hint: go tool trace $T/trace"
