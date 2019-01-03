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
#
# See Documentation/extractloop.md for example output.

set -eu

# Run at low priority to not annoy the user too much
renice 19 $$

cd "$(dirname "$0")"
MD5="$PWD/linux-3.0.md5sums"
MYNAME=$(basename "$0")
source ../fuse-unmount.bash

# Setup dirs
../dl-linux-tarball.bash
cd /tmp
EXTRACTLOOP_TMPDIR=/tmp/extractloop_tmpdir
mkdir -p $EXTRACTLOOP_TMPDIR
CRYPT=$(mktemp -d $EXTRACTLOOP_TMPDIR/XXX)
CSV=$CRYPT.csv
MNT=$CRYPT.mnt
mkdir $MNT

function check_md5sums {
	if command -v md5sum > /dev/null ; then
		md5sum --status -c $1
	else
		# MacOS / darwin which do not have the md5sum utility
		# installed by default
		echo "Skipping md5sum (not installed). Hint: brew install md5sha1sum"
	fi
}

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
	disown
else
	echo "Testing gocryptfs"
	gocryptfs -q -init -extpass="echo test" -scryptn=10 $CRYPT
	gocryptfs -q -extpass="echo test" -nosyslog -fg $CRYPT $MNT &
	FSPID=$(jobs -p)
	disown
	#gocryptfs -q -extpass="echo test" -nosyslog -memprofile /tmp/extractloop-mem $CRYPT $MNT
fi
echo "Test dir: $CRYPT"
# Sleep to make sure the FS is already mounted on MNT
sleep 1
cd $MNT

ln -v -sTf $CSV /tmp/extractloop.csv 2> /dev/null || true # fails on MacOS, ignore

# Cleanup trap
# Note: gocryptfs may have already umounted itself because bash relays SIGINT
# Just ignore unmount errors.
trap "cd / ; rm -Rf $CRYPT ; fuse-unmount -z $MNT || true ; rmdir $MNT" EXIT

function loop {
	ID=$1
	mkdir $ID
	cd $ID

	echo "[looper $ID] Starting"

	N=1
	RSS=0
	while true
	do
		t1=$SECONDS
		tar xf /tmp/linux-3.0.tar.gz --exclude linux-3.0/arch/microblaze/boot/dts/system.dts
		#                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
		# Exclude the one symlink in the tarball - causes problems on MacOS: "Can't set permissions to 0755"
		check_md5sums $MD5
		rm -Rf linux-3.0
		t2=$SECONDS
		delta=$((t2-t1))
		if [[ $FSPID -gt 0 && -d /proc ]]; then
			RSS=$(grep VmRSS /proc/$FSPID/status | tr -s ' ' | cut -f2 -d ' ')
			echo "$N,$SECONDS,$RSS" >> $CSV
		fi
		echo "[looper $ID] Iteration $N done, $delta seconds, RSS $RSS kiB"
		let N=$N+1
	done
}

function memprof {
	while true; do
		kill -USR1 $FSPID
		sleep 60
	done
}

loop 1 &
loop 2 &
#memprof &
wait
