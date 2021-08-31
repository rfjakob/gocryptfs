#!/bin/bash
#
# Find out the maximum supported filename length and print it.
#
# Part of the gocryptfs test suite
# https://nuetzlich.net/gocryptfs/

set -eu
MYNAME=$(basename "$0")

if [[ $# -ne 1 || $1 == -* ]]; then
	echo "Usage: $MYNAME DIRECTORY"
	exit 1
fi

# Only show live progress if connected to a termial
# https://stackoverflow.com/a/911213/1380267
INTERACTIVE=0
if [[ -t 1 ]] ; then
	INTERACTIVE=1
fi

cd "$1"
echo "Testing $PWD"

echo -n "  Maximum filename length: "
# Add one character at a time until we hit an error
NAME=""
while true ; do
	NEXT="${NAME}x"
	if [[ -e $NEXT ]]; then
		echo "error: file $PWD/$NEXT already exists"
		exit 1
	fi
	echo -n 2> /dev/null > "$NEXT" || break
	rm "$NEXT"
	NAME="$NEXT"
done
echo "${#NAME}"

# Set to 0 if undefined
: ${QUICK:=0}

if [[ $QUICK -ne 1 ]]; then
	echo -n "  Maximum dirname length:  "
	# Add one character at a time until we hit an error
	NAME=""
	while true ; do
		NEXT="${NAME}x"
		mkdir "$NEXT" 2> /dev/null || break
		rmdir "$NEXT"
		NAME="$NEXT"
	done
	MAX_DIRNAME=${#NAME}
	echo "${#NAME}"
fi

if [[ $QUICK -eq 1 ]]; then
	CHARS_TODO=100
else
	CHARS_TODO="1 10 100 $MAX_DIRNAME"
fi

for CHARS_PER_SUBDIR in $CHARS_TODO ; do
	echo -n "  Maximum path length with $(printf %3d $CHARS_PER_SUBDIR) chars per subdir: "
	if [[ $INTERACTIVE -eq 1 ]] ; then
		echo -n "    "
	fi
	# Trick from https://stackoverflow.com/a/5349842/1380267
	SUBDIR=$(printf 'x%.0s' $(seq 1 $CHARS_PER_SUBDIR))
	mkdir "$SUBDIR"
	P=$SUBDIR
	# Create a deep path, one $SUBDIR at a time, until we hit an error
	while true ; do
		NEXT="$P/$SUBDIR"
		mkdir "$NEXT" 2> /dev/null || break
		P=$NEXT
		if [[ $INTERACTIVE -eq 1 ]] ; then
			echo -n -e "\b\b\b\b"
			printf %4d ${#P}
		fi
	done
	# Then add one character at a time until we hit an error
	NAME=""
	while true ; do
		NEXT="${NAME}x"
		touch "$P/$NEXT" 2> /dev/null || break
		NAME=$NEXT
	done
	if [[ $NAME != "" ]] ; then
		P=$P/$NAME
	fi
	if [[ $INTERACTIVE -eq 1 ]] ; then
		echo -n -e "\b\b\b\b"
	fi
	printf %4d ${#P}
	echo
	rm -R "$SUBDIR"
done
