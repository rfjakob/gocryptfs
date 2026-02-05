#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")"

CGO_ENABLED=0 source ./build.bash
