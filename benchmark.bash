#!/bin/bash -eu

# Run the set of "canonical" benchmarks that are shown on
# https://nuetzlich.net/gocryptfs/comparison/

cd "$(dirname "$0")"
MYNAME=$(basename "$0")
source tests/fuse-unmount.bash

usage() {
	echo "Usage: $MYNAME [-encfs] [-openssl=true] [-openssl=false] [-dd] [DIR]"
}

OPT_ENCFS=0
OPT_LOOPBACK=0
OPT_OPENSSL=""
OPT_DIR=""
DD_ONLY=""
OPT_XCHACHA=""

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
		-dd)
			DD_ONLY=1
			;;
		-loopback)
			OPT_LOOPBACK=1
			;;
		-xchacha)
			OPT_XCHACHA="-xchacha"
			;;
		-*)
			echo "Invalid option: $1"
			usage
			exit 2
			;;
		*)
			if [[ -n $OPT_DIR ]] ; then
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
mkdir "$MNT"

# Mount
if [[ $OPT_ENCFS -eq 1 ]]; then
	if [[ -n $OPT_OPENSSL ]] ; then
		echo "The option $OPT_OPENSSL only works with gocryptfs"
		exit 1
	fi
	echo -n "Testing EncFS at $CRYPT: "
	encfs --version
	encfs --extpass="echo test" --standard "$CRYPT" "$MNT" > /dev/null
elif [[ $OPT_LOOPBACK -eq 1 ]]; then
	echo "Testing go-fuse loopback"
	"$HOME/go/src/github.com/hanwen/go-fuse/example/loopback/loopback" "$MNT" "$CRYPT" &
	sleep 0.5
else
	echo -n "Testing gocryptfs $OPT_XCHACHA $OPT_OPENSSL at $CRYPT: "
	gocryptfs -version
	gocryptfs $OPT_XCHACHA -q -init -extpass="echo test" -scryptn=10 "$CRYPT"
	gocryptfs $OPT_OPENSSL -q -extpass="echo test" "$CRYPT" "$MNT"
fi

# Make sure we have actually mounted something
if ! mountpoint "$MNT" ; then
	exit 1
fi

# Cleanup trap
trap 'cd /; fuse-unmount -z "$MNT"; rm -rf "$CRYPT" "$MNT"' EXIT

# Benchmarks
if [[ $DD_ONLY -eq 1 ]]; then
	echo -n "WRITE: "
	dd if=/dev/zero "of=$MNT/zero" bs=131072 count=20000 2>&1 | tail -n 1
	rm "$MNT/zero"
else
	./tests/canonical-benchmarks.bash "$MNT"
fi
