#!/bin/bash
#
# Mount a gocryptfs filesystem somewhere on /tmp, then run two parallel
# infinite loops inside that do the following:
# 1) Extract linux-3.0.tar.gz
# 2) Verify the md5sums
# 3) Delete, go to (1)
#
# This test is good at discovering inode-related memory leaks because it creates
# huge numbers of files.

set -eu

cd "$(dirname "$0")"
MD5="$PWD/linux-3.0.md5sums"
MYNAME=$(basename "$0")
source ../fuse-unmount.bash

# Setup dirs
cd /tmp
wget -nv --show-progress -c https://www.kernel.org/pub/linux/kernel/v3.0/linux-3.0.tar.gz
CRYPT=$(mktemp -d /tmp/$MYNAME.XXX)
CSV=$CRYPT.csv
MNT=$CRYPT.mnt
mkdir $MNT

# Mount
FSPID=0
if [ $# -eq 1 ] && [ "$1" == "-encfs" ]; then
	echo "Testing EncFS"
	encfs --extpass="echo test" --standard $CRYPT $MNT > /dev/null
elif [ $# -eq 1 ] && [ "$1" == "-loopback" ]; then
	echo "Testing go-fuse loopback"
	rm -f /tmp/loopback*.memprof
	loopback -l -memprofile=/tmp/loopback $MNT $CRYPT &
	FSPID=$(jobs -p)
else
	echo "Testing gocryptfs"
	gocryptfs -q -init -extpass="echo test" -scryptn=10 $CRYPT
	gocryptfs -q -extpass="echo test" -nosyslog -f $CRYPT $MNT &
	FSPID=$(jobs -p)
	#gocryptfs -q -extpass="echo test" -nosyslog -memprofile /tmp/extractloop-mem $CRYPT $MNT
fi
echo "Test dir: $CRYPT"
# Sleep to make sure the FS is already mounted on MNT
sleep 1
cd $MNT

ln -sTf $CSV /tmp/extractloop.csv

# Cleanup trap
# Note: gocryptfs may have already umounted itself because bash relays SIGINT
# Just ignore unmount errors.
trap "cd /; fuse-unmount -z $MNT; rm -rf $CRYPT $MNT" EXIT

function loop {
	# Note: In a subshell, $$ returns the PID of the parent shell.
	# We need our own PID, which is why we use $BASHPID.
	mkdir $BASHPID
	cd $BASHPID

	echo "[pid $BASHPID] Starting loop"

	N=1
	RSS=0
	while true
	do
		t1=$SECONDS
		tar xf /tmp/linux-3.0.tar.gz
		md5sum --status -c $MD5
		rm -Rf linux-3.0
		t2=$SECONDS
		delta=$((t2-t1))
		if [ $FSPID -gt 0 ]; then
			RSS=$(grep VmRSS /proc/$FSPID/status | tr -s ' ' | cut -f2 -d ' ')
			echo "$N,$SECONDS,$RSS" >> $CSV
		fi
		echo "[pid $BASHPID] Iteration $N done, $delta seconds, RSS $RSS kiB"
		let N=$N+1
	done
}

function memprof {
	while true; do
		kill -USR1 $FSPID
		sleep 60
	done
}

loop &
loop &
#memprof &
wait
