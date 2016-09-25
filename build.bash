#!/bin/bash

set -eu

cd "$(dirname "$0")"

# GOPATH may contain multiple paths separated by ":"
GOPATH2=$(echo $GOPATH | cut -f1 -d:)

# gocryptfs version according to git
GITVERSION=$(git describe --tags --dirty)

# go-fuse version according to git
GITVERSIONFUSE=$(
	cd $GOPATH2/src/github.com/hanwen/go-fuse
	SHORT=$(git rev-parse --short HEAD)

	# Check if the tree is dirty, adapted from
	# http://stackoverflow.com/a/2659808/1380267
	if ! git diff-index --quiet HEAD; then
		echo $SHORT-dirty
	else
		echo $SHORT
	fi
)

# Build Unix timestamp, something like 1467554204.
BUILDTIME=$(date +%s)

# Make sure we have the go binary
go version > /dev/null

# "go version go1.6.2 linux/amd64" -> "1.6"
V=$(go version | cut -d" " -f3 | cut -c3-5)

if [ $V == "1.3" -o $V == "1.4" ]
then
	go build -ldflags="-X main.GitVersion $GITVERSION -X main.GitVersionFuse $GITVERSIONFUSE -X main.BuildTime $BUILDTIME"
else
	# Go 1.5 wants an "=" here
	go build -ldflags="-X main.GitVersion=$GITVERSION -X main.GitVersionFuse=$GITVERSIONFUSE -X main.BuildTime=$BUILDTIME"
fi
(cd gocryptfs-xray; go build)

./gocryptfs -version

mkdir -p $GOPATH2/bin
cp -af gocryptfs $GOPATH2/bin
