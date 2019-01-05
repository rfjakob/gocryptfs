#!/bin/bash
#
# Simplified xfstests generic/273
# See https://github.com/rfjakob/gocryptfs/issues/322

echo "deleting old files"
rm -Rf origin sub_*

SECONDS=0
echo "creating files with dd"
mkdir -p origin
for i in $(seq 1 778) ; do
	dd if=/dev/zero of=origin/file_$i bs=8192 count=1 status=none
done

echo -n "cp starting: "
for i in $(seq 1 100) ; do
	echo -n "$i "
	(mkdir sub_$i && cp -r origin sub_$i ; echo -n "$i ") &
done

echo
echo -n "cp finished: "
wait
echo
echo "Runtime was $SECONDS seconds"
