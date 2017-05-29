#!/bin/bash

set -eu
cd $(dirname "$0")

# Build binary and sets $GITVERSION (example: v0.7-15-gf01f599)
source build.bash

# Set $ID (example: "fedora", "debian") and $VERSION_ID (example: "23", "8")
if [[ -e /etc/os-release ]]; then
	# Modern Debian and Fedora
	source /etc/os-release
elif [[ -e /etc/redhat-release ]]; then
	# RHEL and CentOS
	# "CentOS release 5.11 (Final)" -> "CentOS_release_5.11_Final"
	ID=$(cat /etc/redhat-release | tr ' ' '_' | tr -d '()')
	VERSION_ID=""
else
	echo "Could not get distribution version"
	ID=unknown
	VERSION_ID=.unknown
fi

ARCH=$(go env GOARCH)
# Build gocryptfs.1 man page
./Documentation/MANPAGE-render.bash > /dev/null
cp -a ./Documentation/gocryptfs.1 .

TARGZ=gocryptfs_${GITVERSION}_${ID}${VERSION_ID}_${ARCH}.tar.gz

tar czf $TARGZ gocryptfs gocryptfs.1

echo "Tar created."
echo "Hint for signing: gpg -u 23A02740 --armor --detach-sig $TARGZ"
