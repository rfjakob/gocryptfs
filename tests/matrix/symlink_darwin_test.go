package matrix

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestOpenSymlinkDarwin checks that a symlink can be opened
// using O_SYMLINK.
func TestOpenSymlinkDarwin(t *testing.T) {
	path := test_helpers.DefaultPlainDir + "/TestOpenSymlink"
	target := "/target/does/not/exist"
	err := os.Symlink(target, path)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_SYMLINK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	if st.Size != int64(len(target)) {
		t.Errorf("wrong size: have=%d want=%d", st.Size, len(target))
	}
	if err := unix.Unlink(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(fd, &st); err != nil {
		t.Error(err)
	}
}
