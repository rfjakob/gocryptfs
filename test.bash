#!/bin/bash

set -eu

cd "$(dirname "$0")"

source build.bash

go test ./...
