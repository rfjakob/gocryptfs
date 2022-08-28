//go:build linux
// +build linux

package defaults

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// https://github.com/rfjakob/gocryptfs/issues/641
//
// I was trying to run the Docker daemon with the recommended overlay2 storage driver, and encrypt its `/var/lib/docker` directory using gocryptfs. overlay2 was giving me the following errors:
// ```
// Jan 21 19:09:43 friedhelm.rankenste.in kernel: overlayfs: upper fs does not support tmpfile.
// Jan 21 19:09:43 friedhelm.rankenste.in kernel: overlayfs: upper fs does not support RENAME_WHITEOUT.
// Jan 21 19:09:43 friedhelm.rankenste.in kernel: overlayfs: upper fs missing required features.
// ```

func TestRenameWhiteout(t *testing.T) {
	short := t.Name() + ".short"
	long := t.Name() + strings.Repeat(".long", 200/len(".long"))

	names := [][]string{
		// short to short
		{short + "s2s", short + "s2s2"},
		// short to long
		{short + "s2l", long + "s2l2"},
		// long to short
		{long + "l2s", short + "l2s2"},
		// long to long
		{long + "l2l", short + "l2l2"},
	}

	for _, flags := range []uint{syscallcompat.RENAME_WHITEOUT, syscallcompat.RENAME_WHITEOUT | syscallcompat.RENAME_NOREPLACE} {
		for _, n := range names {
			pSrc := test_helpers.DefaultPlainDir + "/" + n[0]
			pDst := test_helpers.DefaultPlainDir + "/" + n[1]
			if err := ioutil.WriteFile(pSrc, nil, 0200); err != nil {
				t.Fatalf("creating empty file failed: %v", err)
			}
			err := unix.Renameat2(-1, pSrc, -1, pDst, flags)
			if err != nil {
				t.Error(err)
			}
			// readdir should not choke on leftover or missing .name files
			dir, err := os.Open(test_helpers.DefaultPlainDir)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			_, err = dir.Readdir(0)
			if err != nil {
				t.Error(err)
			}
			// pSrc should now be a character device 0 file
			var st unix.Stat_t
			err = unix.Stat(pSrc, &st)
			if err != nil {
				t.Error(err)
			}
			if !(st.Mode&unix.S_IFMT == unix.S_IFCHR) {
				t.Error("not a device file")
			}
			if st.Rdev != 0 {
				t.Errorf("want device 0, have %d", st.Rdev)
			}
			unix.Unlink(pSrc)
			unix.Unlink(pDst)
		}
	}
}

func TestRenameExchange(t *testing.T) {
	short := t.Name() + ".short"
	long := t.Name() + strings.Repeat(".long", 200/len(".long"))

	names := [][]string{
		// short to short
		{short + "s2s", short + "s2s2"},
		// short to long
		{short + "s2l", long + "s2l2"},
		// long to short
		{long + "l2s", short + "l2s2"},
		// long to long
		{long + "l2l", short + "l2l2"},
	}

	for _, n := range names {
		pSrc := test_helpers.DefaultPlainDir + "/" + n[0]
		pDst := test_helpers.DefaultPlainDir + "/" + n[1]
		if err := ioutil.WriteFile(pSrc, nil, 0200); err != nil {
			t.Fatalf("creating empty file failed: %v", err)
		}
		if err := ioutil.WriteFile(pDst, nil, 0200); err != nil {
			t.Fatalf("creating empty file failed: %v", err)
		}
		err := unix.Renameat2(-1, pSrc, -1, pDst, unix.RENAME_EXCHANGE)
		if err != nil {
			t.Error(err)
		}
		// readdir should not choke on leftover or missing .name files
		dir, err := os.Open(test_helpers.DefaultPlainDir)
		if err != nil {
			t.Fatal(err)
		}
		defer dir.Close()
		_, err = dir.Readdir(0)
		if err != nil {
			t.Error(err)
		}
	}
}

// Looks like the FUSE protocol does support O_TMPFILE yet
func TestOTmpfile(t *testing.T) {
	p := test_helpers.DefaultPlainDir + "/" + t.Name()
	fd, err := unix.Openat(-1, p, unix.O_TMPFILE, 0600)
	if err != nil {
		t.Skip(err)
	}
	unix.Close(fd)
}
