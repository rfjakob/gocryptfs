#!/bin/bash

set -eu

cd "$(dirname "$0")"

# gocryptfs version according to git
GITVERSION=$(git describe --tags --dirty)
# go-fuse version according to git
GITVERSIONFUSE=$(git -C $GOPATH/src/github.com/hanwen/go-fuse rev-parse --short HEAD)

# go version go1.5.1 linux/amd64
V=$(go version | cut -d" " -f3 | cut -c3-5)

if [ $V == "1.3" -o $V == "1.4" ]
then
	go build -ldflags="-X main.GitVersion $GITVERSION -X main.GitVersionFuse $GITVERSIONFUSE"
else
	# Go 1.5 wants an "=" here
	go build -ldflags="-X main.GitVersion=$GITVERSION -X main.GitVersionFuse=$GITVERSIONFUSE"
fi

./gocryptfs -version

mkdir -p $GOPATH/bin
cp -af gocryptfs $GOPATH/bin
