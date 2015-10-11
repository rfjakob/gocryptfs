#!/bin/bash

set -eux

tag=$(git describe --tags)
go build
tar czvf gocryptfs_$tag.tar.gz gocryptfs
