// test gocryptfs cipherdir mounted multiple times at the same time
package sharedstorage

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

var flagSharestorage bool

func TestMain(m *testing.M) {
	flagSharestorage = false
	m.Run()
	flagSharestorage = true
	m.Run()
}

// mountSharedstorage mounts `cipherdir` on `mnt` with or without the
// `-sharedstorage` flag, depending on the global var `flagSharestorage`.
func mountSharedstorage(t *testing.T, cipherdir string, mnt string) {
	args := []string{"-extpass=echo test"}
	if flagSharestorage {
		args = append(args, "-sharedstorage")
	}
	test_helpers.MountOrFatal(t, cipherdir, mnt, args...)
}

func TestUnlink(t *testing.T) {
	cipherdir := test_helpers.InitFS(t)
	mnt1 := cipherdir + ".mnt1"
	mnt2 := cipherdir + ".mnt2"
	mountSharedstorage(t, cipherdir, mnt1)
	defer test_helpers.UnmountPanic(mnt1)
	mountSharedstorage(t, cipherdir, mnt2)
	defer test_helpers.UnmountPanic(mnt2)

	// Create dir via mnt1
	if err := unix.Mkdir(mnt1+"/foo", 0700); err != nil {
		t.Fatal(err)
	}
	// Replace dir with file via mnt2
	if err := unix.Rmdir(mnt2 + "/foo"); err != nil {
		t.Fatal(err)
	}
	if fd, err := unix.Creat(mnt2+"/foo", 0600); err != nil {
		t.Fatal(err)
	} else {
		unix.Close(fd)
	}
	// Try to unlink via mnt1
	if err := unix.Unlink(mnt1 + "/foo"); err != nil {
		if flagSharestorage {
			t.Fatal(err)
		} else {
			t.Logf("Unlink failed as expected: errno %d / %v", err, err)
		}
	}
}
