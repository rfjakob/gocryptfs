#!/bin/bash

set -eux

cd cryptfs
go build
go test
cd ..

go build
go test

