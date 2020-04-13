#!/bin/bash -eu

cd "$(dirname "$0")"

export GO111MODULE=on
B="go build -tags without_openssl"

set -x

# See https://github.com/golang/go/wiki/GoArm
GOOS=linux  GOARCH=arm   GOARM=7 $B
GOOS=linux  GOARCH=arm64         $B

# MacOS
GOOS=darwin GOARCH=amd64 $B

# The cross-built binary is not useful on the compile host.
rm gocryptfs
