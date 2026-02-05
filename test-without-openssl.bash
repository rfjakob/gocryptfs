#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")"

CGO_ENABLED=0 ./test.bash "$@"
