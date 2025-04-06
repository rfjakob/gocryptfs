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

export CGO_ENABLED=0

GOOS=linux  GOARCH=amd64         build

# See https://go.dev/wiki/GoArm
GOOS=linux  GOARCH=arm   GOARM=7 build
GOOS=linux  GOARCH=arm64         build

# MacOS on Intel
GOOS=darwin GOARCH=amd64 build
# Catch tests that don't work on MacOS (takes a long time so we only run it once)
time GOOS=darwin GOARCH=amd64 compile_tests

# MacOS on Apple Silicon M1.
GOOS=darwin GOARCH=arm64 build
