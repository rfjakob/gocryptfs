#!/bin/bash -eu

cd "$(dirname "$0")"

CGO_ENABLED=0 source ./build.bash -tags without_openssl

if ldd gocryptfs 2> /dev/null ; then
	echo "build-without-openssl.bash: error: compiled binary is not static"
	exit 1
fi
