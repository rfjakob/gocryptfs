#!/bin/bash

set -eux

# Render MANPAGE.md to a proper man(1) manpage
cd ${0%/*}
pandoc MANPAGE.md -s -t man -o gocryptfs.1 && man ./gocryptfs.1
