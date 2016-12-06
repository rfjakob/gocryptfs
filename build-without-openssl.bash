#!/bin/bash

set -eu

cd "$(dirname "$0")"

export CGO_ENABLED=0
exec ./build.bash -tags without_openssl
