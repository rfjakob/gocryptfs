#!/bin/bash -eux

cd "$(dirname "$0")"

B="go build -tags without_openssl"

GOOS=linux  GOARCH=arm   $B
GOOS=linux  GOARCH=arm64 $B
GOOS=darwin GOARCH=amd64 $B

# The cross-built binary is not useful on the compile host.
rm gocryptfs
