#!/bin/bash -eu

cd "$(dirname "$0")"

# Compiles the gocryptfs binary and sets $GITVERSION
source build-without-openssl.bash

if ldd gocryptfs > /dev/null ; then
	echo "error: compiled gocryptfs binary is not static"
	exit 1
fi

# Build man pages gocryptfs.1 & gocryptfs-xray.1
./Documentation/MANPAGE-render.bash > /dev/null

ARCH=$(go env GOARCH)
OS=$(go env GOOS)

TARBALL=gocryptfs_${GITVERSION}_${OS}-static_${ARCH}.tar
TARGZ=$TARBALL.gz

tar --owner=root --group=root --create -vf "$TARBALL" gocryptfs 
tar --owner=root --group=root --append -vf "$TARBALL" -C gocryptfs-xray gocryptfs-xray
tar --owner=root --group=root --append -vf "$TARBALL" -C Documentation gocryptfs.1 gocryptfs-xray.1

gzip -f "$TARBALL"

echo "Tar created."
echo "Hint for signing: gpg -u 23A02740 --armor --detach-sig $TARGZ"
