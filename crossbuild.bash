#!/bin/bash
#
# Build on all supported architectures & operating systems

function build {
	# Discard resulting binary by writing to /dev/null
	go build -tags without_openssl -o /dev/null
}

function compile_tests {
	for i in $(go list ./...) ; do
		go test -c -tags without_openssl -o /dev/null "$i" > /dev/null
	done
}

set -eux

export GO111MODULE=on
export CGO_ENABLED=0

GOOS=linux  GOARCH=amd64         build

# See https://github.com/golang/go/wiki/GoArm
GOOS=linux  GOARCH=arm   GOARM=7 build
GOOS=linux  GOARCH=arm64         build

# MacOS on Intel
GOOS=darwin GOARCH=amd64 build
# Catch tests that don't work on MacOS (takes a long time so we only run it once)
time GOOS=darwin GOARCH=amd64 compile_tests

# MacOS on Apple Silicon M1.
# Go 1.16 added support for the M1 and added ios/arm64,
# so we use this to check if we should attempt a build.
if go tool dist list | grep ios/arm64 ; then
	GOOS=darwin GOARCH=arm64 build
fi
