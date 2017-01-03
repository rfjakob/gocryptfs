#!/bin/bash -eu
#
# This script checks the MD5 sum of /tmp/linux-3.0.tar.gz and downloads
# a fresh copy if its incorrect or the file is missing.

TGZ=/tmp/linux-3.0.tar.gz

MD5_ACTUAL="$(md5sum $TGZ | cut -f1 -d' ')"
MD5_WANT="f7e6591d86a9dbe123dfd1a0be054e7f"

if [[ $MD5_ACTUAL != $MD5_WANT ]]; then
	echo "Downloading linux-3.0.tar.gz"
	wget -nv --show-progress -c -O $TGZ \
		https://cdn.kernel.org/pub/linux/kernel/v3.0/linux-3.0.tar.gz
fi
