#!/bin/bash

# Run the gocryptfs process in the background

set -eu

dir=$(dirname "$0")

# This needs user input and cannot run in the background
if [[ $* == *--init* ]]; then
	"$dir/gocryptfs" $*
else
	"$dir/gocryptfs" $* & disown
fi
