#!/bin/bash
#
# Mount a loopback filesystem somewhere on /tmp, then run an
# infinite loop inside that does the following:
# 1) Extract linux-3.0.tar.gz
# 2) Delete
# 3) Get memory profile
#
# This test is good at discovering inode-related memory leaks because it creates
# huge numbers of files.

set -eu

# Setup dirs
cd /tmp
wget -nv --show-progress -c https://www.kernel.org/pub/linux/kernel/v3.0/linux-3.0.tar.gz
DIR1=$(mktemp -d /tmp/loopback-mem.XXX)
DIR2=$DIR1.mnt
mkdir $DIR2

# Mount
loopback -l -memprofile /tmp/lmem $DIR2 $DIR1 &
LOOPBACKPID=$(jobs -p)
sleep 1
cd $DIR2

# Cleanup trap
trap "cd /; fusermount -u -z $DIR2; rm -rf $DIR1 $DIR2" EXIT

echo "Starting loop"

N=1
while true; do
	t1=$SECONDS
	tar xf /tmp/linux-3.0.tar.gz
	rm -Rf linux-3.0
	t2=$SECONDS
	delta=$((t2-t1))
	rss=$(grep VmRSS /proc/$LOOPBACKPID/status)
	echo "Iteration $N done, $delta seconds, $rss"
	let N=$N+1
	sleep 1
	kill -USR1 $LOOPBACKPID
done

