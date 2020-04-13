#!/bin/bash -u

OUTPUT=$(
	golint ./... | \
	 grep -v "don't use an underscore in package name" | \
	 grep -v "don't use ALL_CAPS in Go names; use CamelCase" |
	 grep -v "don't use underscores in Go names"
)

# No output --> all good
if [[ -z $OUTPUT ]] ; then
	exit 0
fi

echo "golint.bash:"
echo "$OUTPUT"
exit 1
