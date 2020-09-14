#!/bin/bash -ex

MNT=/mnt/ext4-ramdisk

if mountpoint $MNT ; then
	exit 1
fi

IMG=$(mktemp /tmp/ext4-ramdisk-XXX.img)

dd if=/dev/zero of=$IMG bs=1M count=1030
mkfs.ext4 -q $IMG
mkdir -p $MNT
mount $IMG $MNT
chmod 777 $MNT
rm $IMG # unlink the file, it will be deleted once the fs is unmounted
