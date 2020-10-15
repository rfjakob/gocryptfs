#!/bin/bash
#
# Umount all FUSE filesystems mounted below /tmp and /var/tmp.
#
# Useful when you have lots of broken mounts after something in
# the test suite went wrong.

set -eu

MOUNTS=$(mount | grep ' type fuse\.' | grep 'on /var/tmp/\|on /tmp/\|on /mnt/ext4-ramdisk/' | cut -d' ' -f 3)

for i in $MOUNTS ; do
	echo "Unmounting $i"
	fusermount -u -z "$i"
done
