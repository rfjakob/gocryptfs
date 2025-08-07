#!/bin/bash -eu

cd "$(dirname "$0")"

CGO_ENABLED=0 ./test.bash "$@"
