#!/bin/bash -eu
#
# Find out the maximum supported filename length and print it.
#
# Part of the gocryptfs test suite
# https://nuetzlich.net/gocryptfs/

NAME="maxlen."
LEN=7

while [ $LEN -le 10000 ]; do
	touch $NAME 2> /dev/null || break
	rm $NAME
	NAME="${NAME}x"
	let LEN=LEN+1
done

echo $LEN
