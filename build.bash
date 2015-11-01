#!/bin/bash

set -eu

GITVERSION=$(git describe --tags --dirty)

go build -ldflags="-X main.GitVersion=$GITVERSION" && ./gocryptfs -version
