#!/bin/bash

set -eu
cd $(dirname "$0")

source build.bash # Builds binary and sets GITVERSION (example: v0.7-15-gf01f599)
source /etc/os-release # Sets ID (example: fedora) and VERSION_ID (example: 23)
ARCH=$(go env GOARCH)
# Build gocryptfs.1 man page
./Documentation/MANPAGE-render.bash > /dev/null
cp -a ./Documentation/gocryptfs.1 .

TARGZ=gocryptfs_${GITVERSION}_${ID}${VERSION_ID}_${ARCH}.tar.gz

tar czf $TARGZ gocryptfs gocryptfs.1

echo "Tar created."
echo "Hint for signing: gpg -u 23A02740 --armor --detach-sig $TARGZ"
