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

# Setup dirs
cd /tmp
wget -nv --show-progress -c https://www.kernel.org/pub/linux/kernel/v3.0/linux-3.0.tar.gz
DIR1=$(mktemp -d)
DIR2=$(mktemp -d)

# Mount
if [ $# -eq 1 ] && [ "$1" == "-encfs" ]; then
	echo "Testing EncFS"
	encfs --extpass="echo test" --standard $DIR1 $DIR2 > /dev/null
else
	gocryptfs -q -init -extpass="echo test" -scryptn=10 $DIR1
	gocryptfs -q -extpass="echo test" $DIR1 $DIR2
fi
cd $DIR2

# Cleanup trap
# Note: gocryptfs may have already umounted itself because bash relays SIGINT
# Just ignore fusermount errors.
trap "cd /; fusermount -u -z $DIR2; rm -rf $DIR1 $DIR2" EXIT

function loop {
	# Note: In a subshell, $$ returns the PID of the *parent* shell,
	# we need our own, which is why we have to use $BASHPID.
	mkdir $BASHPID
	cd $BASHPID

	echo "[pid $BASHPID] Starting loop"

	N=1
	while true
	do
		t1=$SECONDS
		tar xf /tmp/linux-3.0.tar.gz
		md5sum --status -c $MD5
		rm -Rf linux-3.0
		t2=$SECONDS
		delta=$((t2-t1))
		echo "[pid $BASHPID] Iteration $N done, $delta seconds"
		let N=$N+1
	done
}

loop &
loop &
wait
