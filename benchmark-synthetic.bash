#!/bin/bash

# Run the synthetic benchmarks that are built into gocryptfs using
# "go test".

set -eu

source build.bash

go test ./tests/integration_tests -bench=. -defaultonly
