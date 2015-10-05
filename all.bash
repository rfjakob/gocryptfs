#!/bin/bash

set -eu

cd gocryptfs_main
echo -n "Compiling... "
go build
echo "done."
