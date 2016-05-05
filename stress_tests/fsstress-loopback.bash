#!/bin/bash
set -eu

# Backing directory
DIR=/tmp/a
# Mountpoint
MNT=/tmp/b
# Debug log
LOG=/tmp/log.txt
# fsstress binary
FSSTRESS=~/src/xfstests/ltp/fsstress

if [ ! -x $FSSTRESS ]
then
	echo "fsstress binary not found, adjust FSSTRESS=$FSSTRESS"
	exit 1
fi

# Cleanup + Setup
fusermount -u -z $MNT &> /dev/null || true
mkdir -p $DIR $MNT
rm -Rf $DIR/*
rm -Rf $MNT/*

# FS-specific compile and mount
MYNAME=$(basename $0)
if [ $MYNAME = fsstress-loopback.bash ]; then
	echo "Recompile go-fuse loopback"
	cd $GOPATH/src/github.com/hanwen/go-fuse/example/loopback
	go build && go install
	$GOPATH/bin/loopback -l $MNT $DIR &
elif [ $MYNAME = fsstress-gocryptfs.bash ]; then
	echo "Recompile gocryptfs"
	cd $GOPATH/src/github.com/rfjakob/gocryptfs
	go build && go install
	$GOPATH/bin/gocryptfs -q -init -extpass "echo test" -scryptn=10 $DIR
	$GOPATH/bin/gocryptfs -q -extpass "echo test" -nosyslog $DIR $MNT
else
	echo Unknown mode: $MYNAME
	exit 1
fi

echo -n "Waiting for mount: "
while ! grep "$MNT fuse" /proc/self/mounts > /dev/null
do
	sleep 1
	echo -n x
done
echo " done, debug log goes to $LOG"

echo "Starting fsstress loop"
N=1
while true
do
	> $LOG

	echo $N
	mkdir $MNT/fsstress.1
	echo -n "    fsstress.1 "
	$FSSTRESS -r -m 8 -n 1000 -d $MNT/fsstress.1

	mkdir $MNT/fsstress.2
	echo -n "    fsstress.2 "
	$FSSTRESS -p 20 -r -m 8 -n 1000 -d $MNT/fsstress.2

	mkdir $MNT/fsstress.3
	echo -n "    fsstress.3 "
	$FSSTRESS -p 4 -z -f rmdir=10 -f link=10 -f creat=10 -f mkdir=10 -f rename=30 -f stat=30 -f unlink=30 -f truncate=20 -m 8 -n 1000 -d $MNT/fsstress.3

	echo "    rm"
	rm -R $MNT/*

	let N=$N+1
done

