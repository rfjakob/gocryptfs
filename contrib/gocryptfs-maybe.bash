#!/bin/bash
#
# Conditionally try to mount a gocryptfs filesystem. If either
# * CIPHERDIR/gocryptfs.conf does not exist OR
# * something is already mounted on MOUNTPOINT
# print a message to stdout (not stderr!) but exit with 0.
#
# This is meant to be called from automated mount systems like pam_mount,
# where you want to avoid error messages if the filesystem does not exist,
# or duplicate mounts if the filesystem has already been mounted.
#
# Note that pam_mount ignores messages on stdout which is why printing
# to stdout is ok.
set -eu
MYNAME=$(basename "$0")
if [[ $# -lt 2 || $1 == -* ]]; then
	echo "Usage: $MYNAME CIPHERDIR MOUNTPOINT [-o COMMA-SEPARATED-OPTIONS]" >&2
	exit 1
fi
if [[ ! -f $1/gocryptfs.conf ]]; then
	echo "$MYNAME: \"$1\" does not look like a gocryptfs filesystem, ignoring mount request"
	exit 0
fi
if mountpoint "$2" > /dev/null; then
	echo "$MYNAME: something is already mounted on \"$2\", ignoring mount request"
	exit 0
fi
exec gocryptfs "$@"
