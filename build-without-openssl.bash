#!/bin/bash -eu

cd "$(dirname "$0")"

CGO_ENABLED=0 source ./build.bash -tags without_openssl
