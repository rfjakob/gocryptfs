#!/bin/bash

set -eu

cd "$(dirname "$0")"
MD5="$PWD/../stress_tests/linux-3.0.md5sums"
MYNAME=$(basename "$0")
source ../fuse-unmount.bash

# Setup dirs
../dl-linux-tarball.bash
cd /tmp
WD=$(mktemp -d "/tmp/$MYNAME.XXX")

# Cleanup trap
trap "set +u; cd /; fuse-unmount -z $WD/c; fuse-unmount -z $WD/b; rm -rf $WD" EXIT

cd "$WD"
mkdir a b c
echo "Extracting tarball"
tar -x -f /tmp/linux-3.0.tar.gz -C a
echo "Mounting a -> b -> c chain"
# Init "a"
gocryptfs -q -extpass="echo test" -reverse -init -scryptn=10 a
# Reverse-mount "a" on "b"
gocryptfs -q -extpass="echo test" -reverse  a b
# Forward-mount "b" on "c"
gocryptfs -q -extpass="echo test" b c
# Check md5 sums
cd c
echo "Checking md5 sums"
set -o pipefail
md5sum -c "$MD5" | pv -l -s 36782 -N "files checked" | (grep -v ": OK" || true)
