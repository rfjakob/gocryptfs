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

# Make sure we have the go binary
go version > /dev/null

# Enable Go Modules on Go 1.11 and 1.12
# https://dev.to/maelvls/why-is-go111module-everywhere-and-everything-about-go-modules-24k#-raw-go111module-endraw-with-go-111-and-112
export GO111MODULE=on

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
	echo "Warning: could not determine gocryptfs version"
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
		echo "Warning: could not determine go-fuse version"
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
	BUILDDATE=$(date --utc --date="@${SOURCE_DATE_EPOCH}" +%Y-%m-%d)
fi

# Only set GOFLAGS if it is not already set by the user
if [[ -z ${GOFLAGS:-} ]] ; then
	GOFLAGS=""
	# For reproducible builds, we get rid of $HOME references in the
	# binary using "-trimpath".
	# However, -trimpath needs Go 1.13+, and we support Go 1.11 and Go 1.12
	# too. So don't add it there.
	GV=$(go version)
	if [[ $GV != *"1.11"* && $GV != *"1.12"* ]] ; then
		GOFLAGS="-trimpath"
	fi
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
for d in gocryptfs-xray contrib/statfs contrib/findholes ; do
	(cd "$d"; go build "-ldflags=$GO_LDFLAGS" "$@")
done

./gocryptfs -version

mkdir -p "$GOPATH1/bin"
cp -af gocryptfs "$GOPATH1/bin"
