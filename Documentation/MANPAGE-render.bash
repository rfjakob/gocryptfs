#!/bin/bash

set -eu
cd $(dirname "$0")

# Render Markdown to a proper man(1) manpage
function render {
	IN=$1
	OUT=$2
	echo "Rendering $IN to $OUT"
	echo ".\\\" This is a man page. View it using 'man ./$OUT'" > $OUT
	echo ".\\\"" >> $OUT
	pandoc MANPAGE.md -s -t man >> $OUT
}

render MANPAGE.md gocryptfs.1
render MANPAGE-XRAY.md gocryptfs-xray.1

