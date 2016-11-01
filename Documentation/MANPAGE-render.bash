#!/bin/bash

set -eu
cd $(dirname "$0")

OUT=gocryptfs.1

# Render MANPAGE.md to a proper man(1) manpage
echo ".\\\" This is a man page. View it using 'man ./$OUT'" > $OUT
echo ".\\\"" >> $OUT
pandoc MANPAGE.md -s -t man >> $OUT && man ./gocryptfs.1
