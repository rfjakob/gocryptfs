#!/bin/bash -eu

# Run the set of "canonical" benchmarks that are shown on
# https://nuetzlich.net/gocryptfs/comparison/

cd "$(dirname "$0")"
MYNAME=$(basename "$0")
source tests/fuse-unmount.bash

function usage {
	echo "Usage: $MYNAME [-encfs] [-openssl=true] [-openssl=false] [DIR]"
}

OPT_ENCFS=0
OPT_OPENSSL=""
OPT_DIR=""

while [[ $# -gt 0 ]] ; do
	case $1 in
		-h)
			usage
			exit 1
			;;
		-encfs)
			OPT_ENCFS=1
			;;
		-openssl=true)
			OPT_OPENSSL="-openssl=true"
			;;
		-openssl=false)
			OPT_OPENSSL="-openssl=false"
			;;
		-*)
			echo "Invalid option: $1"
			usage
			exit 2
			;;
		*)
			if [[ ! -z $OPT_DIR ]] ; then
				echo "Duplicate DIR argument: $1"
				usage
				exit 3
			fi
			OPT_DIR=$1
			;;
	esac
	shift
done

if [[ -z $OPT_DIR ]] ; then
	OPT_DIR=/tmp
fi

# Create directories
CRYPT=$(mktemp -d "$OPT_DIR/$MYNAME.XXX")
MNT=$CRYPT.mnt
mkdir $MNT

# Mount
if [[ $OPT_ENCFS -eq 1 ]]; then
	if [[ ! -z $OPT_OPENSSL ]] ; then
		echo "The option $OPT_OPENSSL only works with gocryptfs"
		exit 1
	fi
	echo "Testing EncFS at $CRYPT"
	encfs --extpass="echo test" --standard $CRYPT $MNT > /dev/null
else
	echo "Testing gocryptfs at $CRYPT"
	gocryptfs -q -init -extpass="echo test" -scryptn=10 $CRYPT
	gocryptfs -q -extpass="echo test" $OPT_OPENSSL $CRYPT $MNT
fi

# Cleanup trap
trap "cd /; fuse-unmount -z $MNT; rm -rf $CRYPT $MNT" EXIT

# Benchmarks
./tests/canonical-benchmarks.bash $MNT

