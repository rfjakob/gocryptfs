#!/bin/bash -eu

cd "$(dirname "$0")"

./test.bash -tags without_openssl "$@"
