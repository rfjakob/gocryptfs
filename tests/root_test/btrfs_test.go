package root_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// createBtrfsImage creates a btrfs image file, formats it, and mounts it.
// Returns the mount path and a cleanup function.
func createBtrfsImage(t *testing.T) (mnt string, cleanup func()) {
	t.Helper()

	if os.Getuid() != 0 {
		t.Skip("must run as root")
	}

	_, err := exec.LookPath("mkfs.btrfs")
	if err != nil {
		t.Skip("mkfs.btrfs not found, skipping test")
	}

	img := filepath.Join(test_helpers.TmpDir, t.Name()+".img")
	f, err := os.Create(img)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// minimum size for each btrfs device is 114294784
	err = f.Truncate(200 * 1024 * 1024)
	if err != nil {
		t.Fatal(err)
	}

	// Format as Btrfs
	cmd := exec.Command("mkfs.btrfs", img)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("%q", cmd.Args)
		t.Log(string(out))
		t.Fatal(err)
	}

	// Mount
	mnt = img + ".mnt"
	err = os.Mkdir(mnt, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("mount", img, mnt)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Log(string(out))
		t.Fatal(err)
	}

	cleanup = func() {
		syscall.Unmount(mnt, 0)
		syscall.Unlink(img)
	}
	return mnt, cleanup
}

// TestBtrfsQuirks needs root permissions because it creates a loop disk
func TestBtrfsQuirks(t *testing.T) {
	mnt, cleanup := createBtrfsImage(t)
	defer cleanup()

	quirk := syscallcompat.DetectQuirks(mnt)
	if quirk != syscallcompat.QuirkBtrfsBrokenFalloc {
		t.Errorf("wrong quirk: %v", quirk)
	}
}

// TestBtrfsQuirksNoCow verifies that when the backing directory has
// the NOCOW attribute (chattr +C), the QuirkBtrfsBrokenFalloc quirk
// is NOT set, because fallocate works correctly with NOCOW.
func TestBtrfsQuirksNoCow(t *testing.T) {
	mnt, cleanup := createBtrfsImage(t)
	defer cleanup()

	_, err := exec.LookPath("chattr")
	if err != nil {
		t.Skip("chattr not found, skipping test")
	}

	// Create a subdirectory with NOCOW attribute
	nocowDir := filepath.Join(mnt, "nocow")
	err = os.Mkdir(nocowDir, 0700)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("chattr", "+C", nocowDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Log(string(out))
		t.Fatal(err)
	}

	quirk := syscallcompat.DetectQuirks(nocowDir)
	if quirk&syscallcompat.QuirkBtrfsBrokenFalloc != 0 {
		t.Errorf("QuirkBtrfsBrokenFalloc should not be set on NOCOW directory, got quirks: %v", quirk)
	}
}
