#!/usr/bin/env bash
#
# Mount a gocryptfs filesystem in /var/tmp and run pjdfstest against it

set -eu

export TMPDIR=${TMPDIR:-/var/tmp}

cd "$(dirname "$0")"
MYNAME=$(basename "$0")
source ../fuse-unmount.bash

pjdfstest_dir=$(realpath ../../../pjdfstest)
if [[ ! -x $pjdfstest_dir/pjdfstest ]]
then
	echo "$MYNAME: pjdfstest binary not found at $pjdfstest_dir/pjdfstest"
	echo "Please clone and build https://github.com/pjd/pjdfstest"
	exit 1
fi

# Backing directory + mountpoint
DIR=$(mktemp -d "$TMPDIR/$MYNAME.XXX")
MNT="$DIR.mnt"
mkdir "$MNT"

../../gocryptfs -q -init -extpass "echo test" -scryptn=10 "$DIR"
sudo ../../gocryptfs -q -extpass "echo test" -nosyslog -allow_other "$DIR" "$MNT"
cd "$MNT"

# Cleanup trap
trap "cd /tmp ; fuse-unmount -z $MNT" EXIT

echo "Starting pjdfstest"
sudo prove -r "$pjdfstest_dir/tests"