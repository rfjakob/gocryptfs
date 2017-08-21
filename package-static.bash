#!/bin/bash -eu

cd "$(dirname "$0")"

# Compiles the gocryptfs binary and sets $GITVERSION
source build-without-openssl.bash

if ldd gocryptfs > /dev/null ; then
	echo "error: compiled binary is not static"
	exit 1
fi

# Build gocryptfs.1 man page
./Documentation/MANPAGE-render.bash > /dev/null
cp -a ./Documentation/gocryptfs.1 .

ARCH=$(go env GOARCH)
OS=$(go env GOOS)

TARGZ=gocryptfs_${GITVERSION}_${OS}-static_${ARCH}.tar.gz

tar --owner=root --group=root -czf $TARGZ gocryptfs gocryptfs.1

echo "Tar created."
echo "Hint for signing: gpg -u 23A02740 --armor --detach-sig $TARGZ"
