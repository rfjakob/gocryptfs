#!/bin/bash -eu
#
# Build on all supported architectures & operating systems

cd "$(dirname "$0")"

export GO111MODULE=on
B="go build -tags without_openssl"

set -x

export CGO_ENABLED=0

GOOS=linux  GOARCH=amd64         $B

# See https://github.com/golang/go/wiki/GoArm
GOOS=linux  GOARCH=arm   GOARM=7 $B
GOOS=linux  GOARCH=arm64         $B

# MacOS on Intel
GOOS=darwin GOARCH=amd64 $B

# MacOS on Apple Silicon M1
GOOS=darwin GOARCH=arm64 $B

# The cross-built binary is not useful on the compile host.
rm gocryptfs
