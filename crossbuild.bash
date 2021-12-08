#!/bin/bash
#
# Build on all supported architectures & operating systems

function build {
	# Discard resulting binary by writing to /dev/null
	go build -tags without_openssl -o /dev/null
}

set -eux

cd "$(dirname "$0")"

export GO111MODULE=on
export CGO_ENABLED=0

GOOS=linux  GOARCH=amd64         build

# See https://github.com/golang/go/wiki/GoArm
GOOS=linux  GOARCH=arm   GOARM=7 build
GOOS=linux  GOARCH=arm64         build

# MacOS on Intel
GOOS=darwin GOARCH=amd64 build

# MacOS on Apple Silicon M1.
# Go 1.16 added support for the M1 and added ios/arm64,
# so we use this to check if we should attempt a build.
if go tool dist list | grep ios/arm64 ; then
	GOOS=darwin GOARCH=arm64 build
fi
