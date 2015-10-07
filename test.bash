#!/bin/bash

set -eux

cd cryptfs
go build
go test

cd ../gocryptfs_main
go build
go test
