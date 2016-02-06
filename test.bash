#!/bin/bash

set -eu

cd "$(dirname "$0")"

#go test ./cryptfs $*

source build.bash
go test ./integration_tests $*
