#!/bin/bash

set -eux

source build.bash

ARCH=$(go version | cut -d ' ' -f 4 | tr / -)

TARGZ=gocryptfs_${GITVERSION}_$ARCH.tar.gz

tar czf $TARGZ gocryptfs
ls -lh $TARGZ
