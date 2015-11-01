#!/bin/bash

set -eux

go build ./cryptfs
go test ./cryptfs

source build.bash
go test
