#!/bin/bash

set -eu

cd "$(dirname "$0")"

CGO_ENABLED=0 ./build.bash -tags without_openssl
