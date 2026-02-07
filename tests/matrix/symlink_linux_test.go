package matrix

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestOpenSymlinkLinux checks that a symlink can be opened
// using O_PATH.
// Only works on Linux because is uses O_PATH and AT_EMPTY_PATH.
// MacOS has O_SYMLINK instead (see TestOpenSymlinkDarwin).
func TestOpenSymlinkLinux(t *testing.T) {
	path := test_helpers.DefaultPlainDir + "/TestOpenSymlink"
	target := "/target/does/not/exist"
	err := os.Symlink(target, path)
	if err != nil {
		t.Fatal(err)
	}
	how := unix.OpenHow{
		Flags: unix.O_PATH | unix.O_NOFOLLOW,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &how)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstatat(fd, "", &st, unix.AT_EMPTY_PATH); err != nil {
		t.Fatal(err)
	}
	if st.Size != int64(len(target)) {
		t.Errorf("wrong size: have=%d want=%d", st.Size, len(target))
	}
	if err := unix.Unlink(path); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fstatat(fd, "", &st, unix.AT_EMPTY_PATH); err != nil {
		// That's a bug, but I have never heard of a use case that would break because of this.
		// Also I don't see how to fix it, as gocryptfs does not get informed about the earlier
		// Openat2().
		t.Logf("posix compliance issue: deleted symlink cannot be accessed: Fstatat: %v", err)
	}
}
