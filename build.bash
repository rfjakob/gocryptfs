#!/bin/bash

set -eu

cd "$(dirname "$0")"

GITVERSION=$(git describe --tags --dirty)

# go version go1.5.1 linux/amd64
V=$(go version | cut -d" " -f3 | cut -c3-5)

if [ $V == "1.3" -o $V == "1.4" ]
then
	go build -ldflags="-X main.GitVersion $GITVERSION"
else
	# Go 1.5 wants an "=" here
	go build -ldflags="-X main.GitVersion=$GITVERSION"
fi

./gocryptfs -version
