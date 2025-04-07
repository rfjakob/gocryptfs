#!/bin/bash
#
# Simplified xfstests generic/273
#
# Used to fail with
#
#   cp: cannot create regular file 'sub_49/file_773': No such file or directory
#
# If you cannot reproduce, try running this in the background:
#
#   while sleep 0.1 ; do echo 3 > /proc/sys/vm/drop_caches ; done
#
# See https://github.com/rfjakob/gocryptfs/issues/322 for details.
# Fixed by https://github.com/hanwen/go-fuse/commit/d0fca860a5759d17592becfa1b8e5b1bd354b24a .

if [[ -z $TMPDIR ]]; then
	TMPDIR=/var/tmp
	export TMPDIR
fi

cd "$(dirname "$0")"
MYNAME=$(basename "$0")
source ../fuse-unmount.bash

# Set the GOPATH variable to the default if it is empty
GOPATH=$(go env GOPATH)

echo "$MYNAME: using gocryptfs at $GOPATH/bin/gocryptfs"
$GOPATH/bin/gocryptfs --version

# Backing directory
DIR=$(mktemp -d "$TMPDIR/$MYNAME.XXX")
$GOPATH/bin/gocryptfs -q -init -extpass "echo test" -scryptn=10 "$DIR"

# Mountpoint
MNT="$DIR.mnt"
mkdir "$MNT"
$GOPATH/bin/gocryptfs -q -extpass "echo test" -nosyslog "$DIR" "$MNT"
echo "Mounted gocryptfs $DIR at $MNT"

# Cleanup trap
trap "cd / ; fuse-unmount -z $MNT ; rm -rf $DIR $MNT" EXIT

cd "$MNT"

SECONDS=0
echo "creating files with dd"
mkdir -p origin
for i in $(seq 1 778) ; do
	dd if=/dev/zero of="origin/file_$i" bs=8192 count=1 status=none
done
# Perform the shell expansion only once and store the list
ORIGIN_FILES=origin/*

echo -n "cp starting: "
for i in $(seq 1 100) ; do
	echo -n "$i "
	(mkdir "sub_$i" && cp $ORIGIN_FILES "sub_$i" ; echo -n "$i ") &
done

echo
echo -n "cp finished: "
wait
echo
echo "Runtime was $SECONDS seconds"
