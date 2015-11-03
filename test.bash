#!/bin/bash

set -eu

go build ./cryptfs
go test ./cryptfs $*

source build.bash
go test $*
