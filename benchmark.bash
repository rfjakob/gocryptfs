#!/bin/bash

set -eux

go build
go test -bench=.
