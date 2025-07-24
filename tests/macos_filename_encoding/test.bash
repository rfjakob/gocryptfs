#!/bin/bash -eu

cd "$(dirname "$0")/../.."
go test -v ./tests/macos_filename_encoding/...
