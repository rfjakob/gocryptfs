#!/bin/bash

set -eu

source build.bash

go test ./integration_tests -bench=. -defaultonly
