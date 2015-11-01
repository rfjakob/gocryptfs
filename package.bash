#!/bin/bash

set -eux

source build.bash

TARGZ=gocryptfs_$GITVERSION.tar.gz

tar czf $TARGZ gocryptfs
ls -lh $TARGZ
