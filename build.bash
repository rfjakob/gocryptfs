#!/bin/bash -eu
#
# Compile gocryptfs and bake the git version string of itself and the go-fuse
# library into the binary.
#
# If you want to fake a build date to reproduce a specific build,
# you can use:
#  BUILDDATE=2017-02-03 ./build.bash
# or
#  SOURCE_DATE_EPOCH=1544192417 ./build.bash
# .

cd "$(dirname "$0")"

# $0 does not work because we may have been sourced
MYNAME=build.bash

# Make sure we have the go binary
go version > /dev/null

# GOPATH may contain multiple paths separated by ":"
GOPATH1=$(go env GOPATH | cut -f1 -d:)

# gocryptfs version according to git or a VERSION file
if [[ -d .git ]] ; then
	GITVERSION=$(git describe --tags --dirty || echo "[no_tags_found]")
	GITBRANCH=$(git rev-parse --abbrev-ref HEAD)
	if [[ -n $GITBRANCH && $GITBRANCH != master ]] ; then
		GITVERSION="$GITVERSION.$GITBRANCH"
	fi
elif [[ -f VERSION ]] ; then
	GITVERSION=$(cat VERSION)
else
	echo "$MYNAME: warning: could not determine gocryptfs version"
	GITVERSION="[unknown]"
fi

# go-fuse version, if available
if [[ -d vendor/github.com/hanwen/go-fuse ]] ; then
	GITVERSIONFUSE="[vendored]"
else
	# go-fuse version according to Go Modules
	FAIL=0
	OUT=$(go list -m github.com/hanwen/go-fuse/v2 | cut -d' ' -f2-) || FAIL=1
	if [[ $FAIL -eq 0 ]]; then
		GITVERSIONFUSE=$OUT
	else
		echo "$MYNAME: warning: could not determine go-fuse version"
		GITVERSIONFUSE="[unknown]"
	fi
fi

# Build date, something like "2017-09-06". Don't override BUILDDATE
# if it is already set. This may be done for reproducible builds.
if [[ -z ${BUILDDATE:-} ]] ; then
	BUILDDATE=$(date +%Y-%m-%d)
fi

# If SOURCE_DATE_EPOCH is set, it overrides BUILDDATE. This is the
# standard environment variable for faking the date in reproducible builds.
if [[ -n ${SOURCE_DATE_EPOCH:-} ]] ; then
	if ! BUILDDATE=$(date -u --date="@${SOURCE_DATE_EPOCH}" +%Y-%m-%d) ; then
		echo "$MYNAME: info: retrying with BSD date syntax..."
		BUILDDATE=$(date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%d)
	fi
fi

# Only set GOFLAGS if it is not already set by the user
if [[ -z ${GOFLAGS:-} ]] ; then
	GOFLAGS="-trimpath"
	# Also, Fedora and Arch want pie enabled, so enable it.
	# * https://fedoraproject.org/wiki/Changes/golang-buildmode-pie
	# * https://github.com/rfjakob/gocryptfs/pull/460
	# But not with CGO_ENABLED=0 (https://github.com/golang/go/issues/30986)!
	if [[ ${CGO_ENABLED:-1} -ne 0 ]] ; then
		GOFLAGS="$GOFLAGS -buildmode=pie"
	fi
	export GOFLAGS
fi

GO_LDFLAGS="-X \"main.GitVersion=$GITVERSION\" -X \"main.GitVersionFuse=$GITVERSIONFUSE\" -X \"main.BuildDate=$BUILDDATE\""

# If LDFLAGS is set, add it as "-extldflags".
if [[ -n ${LDFLAGS:-} ]] ; then
	GO_LDFLAGS="$GO_LDFLAGS \"-extldflags=$LDFLAGS\""
fi

# Actual "go build" call for gocryptfs
go build "-ldflags=$GO_LDFLAGS" "$@"
# Additional binaries
for d in gocryptfs-xray contrib/statfs contrib/findholes contrib/atomicrename ; do
	(cd "$d"; go build "-ldflags=$GO_LDFLAGS" "$@")
done

./gocryptfs -version

mkdir -p "$GOPATH1/bin"
cp -af gocryptfs "$GOPATH1/bin"
