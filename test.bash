#!/bin/bash

set -eu

cd "$(dirname "$0")"

# Clean up dangling filesystem
for i in $(cat /proc/mounts | grep /tmp/gocryptfs-test-parent | cut -f2 -d" "); do
	echo "Warning: unmounting leftover filesystem: $i"
	fusermount -u $i
done

source build.bash

go test ./... $*

# The tests cannot to this themselves as they are run in parallel.
# Don't descend into possibly still mounted example filesystems.
rm -Rf --one-file-system /tmp/gocryptfs-test-parent

if go tool | grep vet > /dev/null ; then
	go tool vet -all -shadow .
else
	echo "\"go tool vet\" not available - skipping"
fi
