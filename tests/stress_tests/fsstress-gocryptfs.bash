#!/bin/bash
#
# Mount a go-fuse loopback filesystem in /tmp and run fsstress against it
# in an infinite loop, only exiting on errors.
#
# When called as "fsstress-gocryptfs.bash", a gocryptfs filesystem is tested
# instead.
#
# This test used to fail on older go-fuse versions after a few iterations with
# errors like this:
# "rm: cannot remove ‘/tmp/b/fsstress.2/pd/d1XXX/f4a’: No such file or directory"
#
# Nowadays it should pass an indefinite number of iterations.

set -eu

cd "$(dirname "$0")"
MYNAME=$(basename $0)
source ../fuse-unmount.bash

# Backing directory
DIR=$(mktemp -d /tmp/fsstress.XXX)
# Mountpoint
MNT="$DIR.mnt"

# Set the GOPATH variable to the default if it is empty
GOPATH=$(go env GOPATH)

# fsstress binary
FSSTRESS=$GOPATH/src/xfstests/ltp/fsstress

if [ ! -x $FSSTRESS ]
then
	echo "fsstress binary not found, adjust FSSTRESS=$FSSTRESS"
	exit 1
fi

# Setup
fuse-unmount -z $MNT &> /dev/null || true
mkdir -p $DIR $MNT
rm -Rf $DIR/*
rm -Rf $MNT/*



# FS-specific compile and mount
if [ $MYNAME = fsstress-loopback.bash ]; then
	echo "Recompile go-fuse loopback"
	cd $GOPATH/src/github.com/hanwen/go-fuse/example/loopback
	go build && go install
	$GOPATH/bin/loopback -l $MNT $DIR &
	disown
elif [ $MYNAME = fsstress-gocryptfs.bash ]; then
	echo "Recompile gocryptfs"
	cd $GOPATH/src/github.com/rfjakob/gocryptfs
	./build.bash
	$GOPATH/bin/gocryptfs -q -init -extpass "echo test" -scryptn=10 $DIR
	$GOPATH/bin/gocryptfs -q -extpass "echo test" -nosyslog $DIR $MNT
elif [ $MYNAME = fsstress-encfs.bash ]; then
	# You probably want do adjust this path to your system
	/home/jakob.donotbackup/encfs/build/encfs --extpass "echo test" --standard $DIR $MNT
else
	echo Unknown mode: $MYNAME
	exit 1
fi

echo -n "Waiting for mount: "
sleep 0.5
while ! grep "$MNT fuse" /proc/self/mounts > /dev/null
do
	sleep 1
	echo -n x
done
echo

# Cleanup trap
trap "kill %1 ; cd /; fuse-unmount -z $MNT; rm -rf $DIR $MNT" EXIT

echo "Starting fsstress loop"
N=1
while true
do
	echo $N
	mkdir $MNT/fsstress.1
	echo -n "    fsstress.1 "
	$FSSTRESS -r -m 8 -n 1000 -d $MNT/fsstress.1 &
	wait

	mkdir $MNT/fsstress.2
	echo -n "    fsstress.2 "
	$FSSTRESS -p 20 -r -m 8 -n 1000 -d $MNT/fsstress.2 &
	wait

	mkdir $MNT/fsstress.3
	echo -n "    fsstress.3 "
	$FSSTRESS -p 4 -z -f rmdir=10 -f link=10 -f creat=10 -f mkdir=10 \
		-f rename=30 -f stat=30 -f unlink=30 -f truncate=20 -m 8 \
		-n 1000 -d $MNT/fsstress.3 &
	wait

	echo "    rm"
	rm -R $MNT/*

	let N=$N+1
done

