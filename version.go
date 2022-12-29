package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	gitVersionNotSet     = "[GitVersion not set - please compile using ./build.bash]"
	gitVersionFuseNotSet = "[GitVersionFuse not set - please compile using ./build.bash]"
	buildDateNotSet      = "0000-00-00"
)

var (
	// GitVersion is the gocryptfs version according to git, set by build.bash
	GitVersion = gitVersionNotSet
	// GitVersionFuse is the go-fuse library version, set by build.bash
	GitVersionFuse = gitVersionFuseNotSet
	// BuildDate is a date string like "2017-09-06", set by build.bash
	BuildDate = buildDateNotSet
)

func init() {
	versionFromBuildInfo()
}

// raceDetector is set to true by race.go if we are compiled with "go build -race"
var raceDetector bool

// printVersion prints a version string like this:
// gocryptfs v1.7-32-gcf99cfd; go-fuse v1.0.0-174-g22a9cb9; 2019-05-12 go1.12 linux/amd64
func printVersion() {
	var tagsSlice []string
	if stupidgcm.BuiltWithoutOpenssl {
		tagsSlice = append(tagsSlice, "without_openssl")
	}
	tags := ""
	if tagsSlice != nil {
		tags = " " + strings.Join(tagsSlice, " ")
	}
	built := fmt.Sprintf("%s %s", BuildDate, runtime.Version())
	if raceDetector {
		built += " -race"
	}
	fmt.Printf("%s %s%s; go-fuse %s; %s %s/%s\n",
		tlog.ProgramName, GitVersion, tags, GitVersionFuse, built,
		runtime.GOOS, runtime.GOARCH)
}

// versionFromBuildInfo tries to get some information out of the information baked in
// by the Go compiler. Does nothing when build.bash was used to build.
func versionFromBuildInfo() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		tlog.Debug.Println("versionFromBuildInfo: ReadBuildInfo() failed")
		return
	}
	// Parse BuildSettings
	var vcsRevision, vcsTime string
	var vcsModified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			vcsRevision = s.Value
		case "vcs.time":
			vcsTime = s.Value
		case "vcs.modified":
			vcsModified, _ = strconv.ParseBool(s.Value)
		}
	}
	// Fill our version strings
	if GitVersion == gitVersionNotSet {
		GitVersion = info.Main.Version
		if GitVersion == "(devel)" && vcsRevision != "" {
			GitVersion = fmt.Sprintf("vcs.revision=%s", vcsRevision)
		}
		if vcsModified {
			GitVersion += "-dirty"
		}
	}
	if GitVersionFuse == gitVersionFuseNotSet {
		for _, m := range info.Deps {
			if m.Path == "github.com/hanwen/go-fuse/v2" {
				GitVersionFuse = m.Version
				if m.Replace != nil {
					GitVersionFuse = m.Replace.Version
				}
				break
			}
		}
	}
	if BuildDate == buildDateNotSet {
		if vcsTime != "" {
			BuildDate = fmt.Sprintf("vcs.time=%s", vcsTime)
		}
	}
}
