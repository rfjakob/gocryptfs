#!/bin/bash

set -eu

cd "$(dirname "$0")"

go test -bench .
