#!/bin/bash

set -eux

cd gocryptfs_main

go build
go test -bench=.
