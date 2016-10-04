#!/bin/bash

set -eu

cd "$(dirname "$0")"

exec ./build.bash -tags without_openssl
