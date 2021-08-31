#!/bin/bash

set -eu

cd "$(dirname "$0")"

SIGNME=""

# git_archive_extra PREFIX EXTRA1 [EXTRA2 ...]
#
# Call git-archive and add additional files to the tarball.
# Output tarball is called "$PREFIX.tar.gz" and contains one folder
# called "$PREFIX".
git_archive_extra() {
	local PREFIX=$1
	shift
	# Add files tracked in git
	git archive --prefix "$PREFIX/" -o "$PREFIX.tar" HEAD
	# Add "extra" files
	tar --owner=root --group=root --transform "s!^!$PREFIX/!" --append -f "$PREFIX.tar" "$@"
	# Compress
	gzip -f "$PREFIX.tar"
}

package_source() {
	local GITVERSION
	GITVERSION=$(git describe --tags --dirty)
	echo "$GITVERSION" > VERSION

	# Render the manpages and include them in the tarball. This
	# avoids a build-dependency to pandoc.
	./Documentation/MANPAGE-render.bash

	# gocryptfs source tarball
	local PREFIX_SRC_ONLY=gocryptfs_${GITVERSION}_src
	git_archive_extra "$PREFIX_SRC_ONLY" VERSION Documentation/*.1

	# gocryptfs source + dependencies tarball
	go mod vendor
	local PREFIX_SRC_DEPS=gocryptfs_${GITVERSION}_src-deps
	git_archive_extra "$PREFIX_SRC_DEPS" VERSION Documentation/*.1 vendor

	rm VERSION
	rm -R vendor

	echo "Tars created."
	SIGNME+=" $PREFIX_SRC_ONLY.tar.gz $PREFIX_SRC_DEPS.tar.gz"
}

package_static_binary() {
	# Compiles the gocryptfs binary and sets $GITVERSION
	source build-without-openssl.bash

	if ldd gocryptfs > /dev/null ; then
		echo "error: compiled gocryptfs binary is not static"
		exit 1
	fi

	# Build man pages gocryptfs.1 & gocryptfs-xray.1
	./Documentation/MANPAGE-render.bash > /dev/null

	local ARCH
	ARCH=$(go env GOARCH)
	local OS
	OS=$(go env GOOS)

	local TARBALL
	TARBALL=gocryptfs_${GITVERSION}_${OS}-static_${ARCH}.tar
	local TARGZ
	TARGZ=$TARBALL.gz

	tar --owner=root --group=root --create -vf "$TARBALL" gocryptfs
	tar --owner=root --group=root --append -vf "$TARBALL" -C gocryptfs-xray gocryptfs-xray
	tar --owner=root --group=root --append -vf "$TARBALL" -C Documentation gocryptfs.1 gocryptfs-xray.1

	gzip -f "$TARBALL"

	echo "Tar created."
	SIGNME+=" $TARGZ"
}

signing_hint() {
	local GITVERSION
	GITVERSION=$(git describe --tags --dirty)

	echo "Hint for signing:"
	echo "  for i in gocryptfs_${GITVERSION}_*.tar.gz ; do gpg -u 23A02740 --armor --detach-sig \$i ; done"
}

if git describe --dirty | grep dirty ; then
	echo "Tree is dirty - I will not package this!"
	exit 1
fi

package_source
package_static_binary
signing_hint
