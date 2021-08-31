#!/bin/bash -eu
#
# Compatibility wrapper around "fusermount" on Linux and "umount" on
# Mac OS X and friends.
#
# This script can be sourced or executed directly.
#
fuse-unmount() {
	local MYNAME=$(basename "$BASH_SOURCE")
	if [[ $# -eq 0 ]] ; then
		echo "$MYNAME: missing argument"
		exit 1
	fi
	if [[ $OSTYPE == linux* ]] ; then
		fusermount -u "$@"
	else
		# Mountpoint is in last argument, ignore anything else
		# (like additional flags for fusermount).
		local MNT=${@:$#}
		umount "$MNT"
	fi
}
# If the process name and the source file name is identical
# we have been executed, not sourced.
if [[ $(basename "$0") == $(basename "$BASH_SOURCE") ]] ; then
	fuse-unmount "$@"
fi
