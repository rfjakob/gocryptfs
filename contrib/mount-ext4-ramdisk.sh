#!/bin/bash -ex

MNT=/mnt/ext4-ramdisk

if mountpoint "$MNT" ; then
	exit 1
fi

IMG=$(mktemp /tmp/ext4-ramdisk-XXX.img)

# unlink the file when done, space will be
# reclaimed once the fs is unmounted. Also
# cleans up in the error case.
trap 'rm "$IMG"' EXIT

dd if=/dev/zero of="$IMG" bs=1M count=1030 status=none
mkfs.ext4 -q "$IMG"
mkdir -p "$MNT"
mount "$IMG" "$MNT"
chmod 777 "$MNT"
