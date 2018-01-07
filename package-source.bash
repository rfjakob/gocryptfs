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
echo $GITVERSION > VERSION

# gocryptfs source tarball
PREFIX_SRC_ONLY=gocryptfs_${GITVERSION}_src
git_archive_extra $PREFIX_SRC_ONLY VERSION

# gocryptfs source + dependencies tarball
dep ensure
PREFIX_SRC_DEPS=gocryptfs_${GITVERSION}_src-deps
git_archive_extra $PREFIX_SRC_DEPS VERSION vendor

rm VERSION

echo "Tars created."
echo "Hint for signing: gpg -u 23A02740 --armor --detach-sig $PREFIX_SRC_ONLY.tar.gz"
echo "                  gpg -u 23A02740 --armor --detach-sig $PREFIX_SRC_DEPS.tar.gz"
