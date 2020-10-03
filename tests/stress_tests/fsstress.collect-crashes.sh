#!/bin/bash
cd ~/go/src/github.com/rfjakob/gocryptfs/tests/stress_tests || exit 1
export TMPDIR=/mnt/ext4-ramdisk
# Check that TMPDIR is writeable
touch "$TMPDIR/$$" || exit 1
rm "$TMPDIR/$$"
LOGDIR=/tmp/$$
mkdir "$LOGDIR" || exit 1
echo "Logging to LOGDIR=$LOGDIR, TMPDIR=$TMPDIR"
for i in $(seq 1 1000) ; do
	set -x
	LOG="$LOGDIR/fsstress.log.$(date --iso).$i"
	if [[ -e $LOG ]]; then
		continue
	fi
	rm -Rf "$TMPDIR"/fsstress*
	#   100000 lines ...... ~7 MB
	#  1000000 lines ..... ~70 MB
	# 10000000 lines .... ~700 MB
	DEBUG=1 ./fsstress-loopback.bash 2>&1 | tail -1000000 > "$LOG"
done
