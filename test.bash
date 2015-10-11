#!/bin/bash

set -eux

go build
go test

cd cryptfs
go build
go test
