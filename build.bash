#!/bin/bash
#
# Compile gocryptfs and bake the git version string of itself and the go-fuse
# library into the binary.
#
# If you want to fake a build date to reproduce a specific build,
# you can use:
# BUILDDATE=2017-02-03 ./build.bash

set -eu

cd "$(dirname "$0")"
MYDIR=$PWD

# GOPATH may contain multiple paths separated by ":"
GOPATH1=$(go env GOPATH | cut -f1 -d:)

# gocryptfs version according to git
GITVERSION=$(git describe --tags --dirty)

# go-fuse version according to git
# Note: git in CentOS 7 does not have "git -C" yet, so we use plain "cd".
FAIL=0
cd $GOPATH1/src/github.com/hanwen/go-fuse
OUT=$(git describe --tags --dirty 2>&1) || FAIL=1
if [[ $FAIL -ne 0 ]]; then
	echo "$PWD: git describe: $OUT"
	echo "Hint: are you missing git tags?"
	exit 1
fi
GITVERSIONFUSE=$OUT
cd "$MYDIR"

# Build date, something like "2017-09-06"
if [[ -z ${BUILDDATE:-} ]] ; then
	BUILDDATE=$(date +%Y-%m-%d)
fi

# Make sure we have the go binary
go version > /dev/null

LDFLAGS="-X main.GitVersion=$GITVERSION -X main.GitVersionFuse=$GITVERSIONFUSE -X main.BuildDate=$BUILDDATE"
go build "-ldflags=$LDFLAGS" $@

(cd gocryptfs-xray; go build $@)

./gocryptfs -version

mkdir -p $GOPATH1/bin
cp -af gocryptfs $GOPATH1/bin
