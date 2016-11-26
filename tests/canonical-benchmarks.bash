#!/bin/bash -eu
#
# Run the set of "canonical" benchmarks that are shown on
# https://nuetzlich.net/gocryptfs/comparison/
# against the directory passed as "$1".
#
# This is called by the top-level script "benchmark.bash".

if [ $# -ne 1 ]; then
	MYNAME=$(basename $0)
	echo "usage: $MYNAME TESTDIR"
	exit 1
fi

cd "$1"

TGZ=/tmp/linux-3.0.tar.gz

if [ "$(md5sum /tmp/linux-3.0.tar.gz | cut -f1 -d' ')" != \
	"f7e6591d86a9dbe123dfd1a0be054e7f" ]; then
	echo "Downloading linux-3.0.tar.gz"
	wget -nv --show-progress -c -O $TGZ \
		https://cdn.kernel.org/pub/linux/kernel/v3.0/linux-3.0.tar.gz
fi

function etime {
	LC_ALL=C /usr/bin/time -f %e 2>&1 $@ > /dev/null
}

echo -n "WRITE: "
dd if=/dev/zero of=zero bs=128K count=2000 2>&1 | tail -n 1
rm zero
sleep 1
echo -n "UNTAR: "
etime tar xzf $TGZ
sleep 1
echo -n "LS:    "
etime ls -lR linux-3.0
sleep 1
echo -n "RM:    "
etime rm -Rf linux-3.0
