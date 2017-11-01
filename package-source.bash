#!/bin/bash -eu

# git_archive_extra PREFIX EXTRA1 [EXTRA2 ...]
# Call git-archive and add additional files to the tarball.
git_archive_extra() {
	local PREFIX=$1
	shift
	# Add files tracked in git
	git archive --prefix "$PREFIX/" -o $PREFIX.tar master
	# Add "extra" files
	tar --transform "s!^!$PREFIX/!" --append -f $PREFIX.tar "$@"
	# Compress
	gzip -f $PREFIX.tar
}

cd "$(dirname "$0")"

GITVERSION=$(git describe --tags --dirty)
PREFIX=gocryptfs_${GITVERSION}_src-deps

dep ensure
echo $GITVERSION > VERSION
git_archive_extra $PREFIX VERSION vendor
rm VERSION

echo "Tar created."
echo "Hint for signing: gpg -u 23A02740 --armor --detach-sig $PREFIX.tar.gz"
