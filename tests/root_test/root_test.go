package root_test

import (
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func asUser(uid int, gid int, supplementaryGroups []int, f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := syscall.Setgroups(supplementaryGroups)
	if err != nil {
		return err
	}
	defer syscall.Setgroups(nil)

	err = syscall.Setregid(-1, gid)
	if err != nil {
		return err
	}
	defer syscall.Setregid(-1, 0)

	err = syscall.Setreuid(-1, uid)
	if err != nil {
		return err
	}
	defer syscall.Setreuid(-1, 0)

	return f()
}

func TestSupplementaryGroups(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("must run as root")
	}
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-allow_other", "-extpass=echo test")
	defer test_helpers.UnmountPanic(pDir)

	dir1 := pDir + "/dir1"
	err := os.Mkdir(dir1, 0770)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Chown(dir1, 0, 1234)
	if err != nil {
		t.Fatal(err)
	}

	err = asUser(1235, 1235, []int{1234}, func() error { return os.Mkdir(dir1+"/foo", 0700) })
	if err != nil {
		t.Error(err)
	}
}
