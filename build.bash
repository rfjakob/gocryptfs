#!/bin/bash

set -eu

cd "$(dirname "$0")"

# GOPATH may contain multiple paths separated by ":"
GOPATH1=$(go env GOPATH | cut -f1 -d:)

# gocryptfs version according to git
GITVERSION=$(git describe --tags --dirty)

# go-fuse version according to git
# Note: git in CentOS 7 does not have "git -C" yet. That's why we use
# plain "cd" in a subshell.
GITVERSIONFUSE=$(
	cd $GOPATH1/src/github.com/hanwen/go-fuse
	SHORT=$(git rev-parse --short HEAD)

	if [[ $SHORT == 5e829bc ]] ; then
		echo "Error: The version $SHORT of the go-fuse library has a known crasher that" >&2
		echo "has been fixed by https://github.com/hanwen/go-fuse/pull/131 . Please upgrade." >&2
		exit 1
	fi

	# Check if the tree is dirty, adapted from
	# http://stackoverflow.com/a/2659808/1380267
	if ! git diff-index --quiet HEAD ; then
		echo $SHORT-dirty
	else
		echo $SHORT
	fi
)

# Build Unix timestamp, something like 1467554204.
BUILDTIME=$(date +%s)

# Make sure we have the go binary
go version > /dev/null

# Parse "go version go1.6.2 linux/amd64" to "1.6"
V=$(go version | cut -d" " -f3 | cut -c3-5)
# Reject old Go versions already here. It would fail with compile
# errors anyway.
if [[ $V == "1.3" || $V == "1.4" ]] ; then
	echo "Error: you need Go 1.5 or higher to compile gocryptfs"
	echo -n "You have: "
	go version
fi

LDFLAGS="-X main.GitVersion=$GITVERSION -X main.GitVersionFuse=$GITVERSIONFUSE -X main.BuildTime=$BUILDTIME"
go build "-ldflags=$LDFLAGS" $@

(cd gocryptfs-xray; go build $@)

./gocryptfs -version

mkdir -p $GOPATH1/bin
cp -af gocryptfs $GOPATH1/bin
