package cli

import (
	"fmt"
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
	}
	table := []testCase{
		{allow_other: false},
		{allow_other: true},
	}

	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"

	doTestMountInfo := func(t *testing.T, row testCase) {
		test_helpers.MountOrFatal(t, dir, mnt, "-extpass=echo test", fmt.Sprintf("-allow_other=%v", row.allow_other))
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
		if !strings.Contains(info.VFSOptions, "max_read=") {
			t.Errorf("VFSOptions is missing max_read")
		}
		if row.allow_other && !strings.Contains(info.VFSOptions, "allow_other") {
			t.Errorf("VFSOptions is missing allow_other")
		}
	}

	for _, row := range table {
		doTestMountInfo(t, row)
	}

}
