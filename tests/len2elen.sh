#!/bin/bash -eu
#
# Check plaintext file name length -> encrypted file name length relation
#
# Part of the gocryptfs test suite
# https://nuetzlich.net/gocryptfs/

NAME="x"
LEN=1

if [[ ! -f a/gocryptfs.conf ]] ; then
	echo "fatal: must have gocryptfs dir 'a' mounted at 'b'"
	exit 1
fi
if ! mountpoint b > /dev/null ; then
	echo "fatal: must have gocryptfs dir 'a' mounted at 'b'"
	exit 1
fi

rm -f b/*

while [[ $LEN -le 255 ]]; do
	touch "b/$NAME" || break
	ELEN=$(ls a | wc -L)
	echo "$LEN $ELEN"
	rm "b/$NAME"
	NAME="${NAME}x"
	LEN=${#NAME}
done
