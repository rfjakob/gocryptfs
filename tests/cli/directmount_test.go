package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/moby/sys/mountinfo"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestDirectMount checks that the effective mount options are what we expect.
//
// This test should be run twice:
// 1) As a normal user (uses fusermount):          make test
// 2) As root (mount syscall is called directly):  make root_test
func TestDirectMount(t *testing.T) {
	type testCase struct {
		allow_other bool
		noexec      bool
		suid        bool
		dev         bool
	}
	table := []testCase{
		{ /* all false */ },
		{allow_other: true},
		{noexec: true},
		{suid: true},
		{dev: true},
	}

	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"

	checkOptionPresent := func(t *testing.T, opts string, option string, want bool) {
		split := strings.Split(opts, ",")
		have := false
		for _, v := range split {
			if strings.HasPrefix(v, option) {
				have = true
				break
			}
		}
		if want != have {
			t.Errorf("checkOptionPresent: %s: want=%v have=%v. Full string: %s", option, want, have, opts)
		}
	}

	doTestMountInfo := func(t *testing.T, row testCase) {
		test_helpers.MountOrFatal(t, dir, mnt,
			"-extpass=echo test",
			fmt.Sprintf("-allow_other=%v", row.allow_other),
			fmt.Sprintf("-noexec=%v", row.noexec),
			fmt.Sprintf("-dev=%v", row.dev),
			fmt.Sprintf("-suid=%v", row.suid))
		defer test_helpers.UnmountErr(mnt)

		mounts, err := mountinfo.GetMounts(mountinfo.SingleEntryFilter(mnt))
		if err != nil {
			t.Fatal(err)
		}
		if len(mounts) != 1 {
			t.Fatalf("Could not find mountpoint %q in /proc/self/mountinfo", mnt)
		}
		info := mounts[0]

		if info.FSType != "fuse.gocryptfs" {
			t.Errorf("wrong FSType: %q", info.FSType)
		}
		if info.Source != dir {
			t.Errorf("wrong Source: have %q, want %q", info.Source, dir)
		}
		checkOptionPresent(t, info.VFSOptions, "max_read=", true)
		checkOptionPresent(t, info.VFSOptions, "allow_other", row.allow_other)
		// gocryptfs enables default_permissions when allow_other is enabled
		checkOptionPresent(t, info.VFSOptions, "default_permissions", row.allow_other)
		checkOptionPresent(t, info.Options, "noexec", row.noexec)
		// Enabling suid and dev only works as root
		if os.Getuid() == 0 {
			checkOptionPresent(t, info.Options, "nosuid", !row.suid)
			checkOptionPresent(t, info.Options, "nodev", !row.dev)
		}
	}

	for _, row := range table {
		doTestMountInfo(t, row)
	}

}
