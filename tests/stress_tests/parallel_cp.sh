#!/bin/bash
#
# Simplified xfstests generic/273
#
# Fails with
#
#   cp: cannot create regular file 'sub_49/file_773': No such file or directory
#
# If you cannot reproduce, try running this in the background:
#
#   while sleep 0.1 ; do echo 3 > /proc/sys/vm/drop_caches ; done"
#
# See https://github.com/rfjakob/gocryptfs/issues/322 for details.

echo "deleting old files"
rm -Rf origin sub_*

SECONDS=0
echo "creating files with dd"
mkdir -p origin
for i in $(seq 1 778) ; do
	dd if=/dev/zero of=origin/file_$i bs=8192 count=1 status=none
done
# Perform the shell expansion only once and store the list
ORIGIN_FILES=origin/*

echo -n "cp starting: "
for i in $(seq 1 100) ; do
	echo -n "$i "
	(mkdir sub_$i && cp $ORIGIN_FILES sub_$i ; echo -n "$i ") &
done

echo
echo -n "cp finished: "
wait
echo
echo "Runtime was $SECONDS seconds"
