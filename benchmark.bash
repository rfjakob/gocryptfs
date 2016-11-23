#!/bin/bash -eu

# Run the set of "canonical" benchmarks that are shown on
# https://nuetzlich.net/gocryptfs/comparison/

cd "$(dirname "$0")"
MYNAME=$(basename "$0")

function usage {
	echo "Usage: $MYNAME [-encfs] [DIR]"
	exit 1
}

# Print help text on too many arguments or "-h"
if [[ $# -gt 2 ]]; then
	usage
elif [[ $# -ge 1 ]] && [[ $1 == "-h" ]]; then
	usage
fi

# Set $DIR and $MODE
MODE=gocryptfs
DIR=/tmp
if [[ $# -eq 2 ]]; then
	if [[ $1 != "-encfs" ]]; then
		usage
	fi
	MODE=encfs
	DIR=$2
elif [[ $# -eq 1 ]]; then
	if [[ $1 == "-encfs" ]]; then
		MODE=encfs
	else
		DIR=$1
	fi
fi

# Create directories
CRYPT=$(mktemp -d "$DIR/$MYNAME.XXX")
MNT=$CRYPT.mnt
mkdir $MNT

# Mount
if [[ $MODE == encfs ]]; then
	echo "Testing EncFS at $CRYPT"
	encfs --extpass="echo test" --standard $CRYPT $MNT > /dev/null
else
	echo "Testing gocryptfs at $CRYPT"
	gocryptfs -q -init -extpass="echo test" -scryptn=10 $CRYPT
	gocryptfs -q -extpass="echo test" $CRYPT $MNT
fi

# Cleanup trap
trap "cd /; fusermount -u -z $MNT; rm -rf $CRYPT $MNT" EXIT

# Benchmarks
./tests/canonical-benchmarks.bash $MNT

