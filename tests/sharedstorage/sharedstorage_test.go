// test gocryptfs cipherdir mounted multiple times at the same time
package sharedstorage

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

var flagSharestorage bool

// EntryTimeout is 1 second, give the kernel 1.1 second to actually
// expire an entry. The tests fail sometime with 1.0 second!
const waitForExpire = time.Second + 100*time.Millisecond

func TestMain(m *testing.M) {
	ret := 0
	flagSharestorage = false
	ret += m.Run()
	flagSharestorage = true
	ret += m.Run()
	os.Exit(ret)
}

type testCase struct {
	t *testing.T

	cipherdir string
	mnt1      string
	mnt2      string
}

func newTestCase(t *testing.T) *testCase {
	tc := testCase{}
	tc.cipherdir = test_helpers.InitFS(t)
	tc.mnt1 = tc.cipherdir + ".mnt1"
	tc.mnt2 = tc.cipherdir + ".mnt2"
	mountSharedstorage(t, tc.cipherdir, tc.mnt1)
	mountSharedstorage(t, tc.cipherdir, tc.mnt2)
	t.Logf("newTestCase: sharedstorage=%v cipherdir=%q", flagSharestorage, tc.cipherdir)
	return &tc
}

func (tc *testCase) cleanup() {
	for _, mnt := range []string{tc.mnt1, tc.mnt2} {
		err := test_helpers.UnmountErr(mnt)
		if err != nil {
			tc.t.Error(err)
		}
	}
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

func TestDirUnlink(t *testing.T) {
	tc := newTestCase(t)
	defer tc.cleanup()

	// Create dir via mnt1
	if err := unix.Mkdir(tc.mnt1+"/foo", 0700); err != nil {
		t.Fatal(err)
	}
	// Replace dir with file via mnt2
	if err := unix.Rmdir(tc.mnt2 + "/foo"); err != nil {
		t.Fatal(err)
	}
	if fd, err := unix.Creat(tc.mnt2+"/foo", 0600); err != nil {
		t.Fatal(err)
	} else {
		unix.Close(fd)
	}
	// Try to unlink via mnt1
	if err := unix.Unlink(tc.mnt1 + "/foo"); err != nil {
		// Must work with -sharedstorage
		if flagSharestorage {
			t.Fatal(err)
		} else {
			// Must always work after cache timeout
			time.Sleep(waitForExpire)
			if err := unix.Unlink(tc.mnt1 + "/foo"); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestStaleHardlinks always failed before
// https://review.gerrithub.io/c/hanwen/go-fuse/+/513646/2
func TestStaleHardlinks(t *testing.T) {
	tc := newTestCase(t)
	defer tc.cleanup()

	link0 := tc.mnt1 + "/link0"
	if fd, err := unix.Creat(link0, 0600); err != nil {
		t.Fatal(err)
	} else {
		unix.Close(fd)
	}
	// Create hardlinks via mnt1
	for i := 1; i < 20; i++ {
		linki := fmt.Sprintf(tc.mnt1+"/link%d", i)
		if err := unix.Link(link0, linki); err != nil {
			t.Fatal(err)
		}
	}
	// Delete hardlinks via mnt2
	for i := 1; i < 20; i++ {
		linki := fmt.Sprintf(tc.mnt2+"/link%d", i)
		if err := unix.Unlink(linki); err != nil {
			t.Fatal(err)
		}
	}
	// Open link0 via mnt1
	fd, err := unix.Open(link0, unix.O_RDONLY, 0)
	if err != nil {
		// Must work with -sharedstorage
		if flagSharestorage {
			t.Fatal(err)
		} else {
			// Must always work after cache timeout
			time.Sleep(waitForExpire)
			fd, err = unix.Open(link0, unix.O_RDONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	unix.Close(fd)
}
