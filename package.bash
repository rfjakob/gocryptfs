#!/bin/bash

set -eux

tag=$(git describe --tags)
cd gocryptfs_main
go build
tar czvf ../gocryptfs_$tag.tar.gz gocryptfs gocryptfs_main
