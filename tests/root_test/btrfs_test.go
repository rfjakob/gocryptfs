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

// TestBtrfsQuirks needs root permissions because it creates a loop disk
func TestBtrfsQuirks(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("must run as root")
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
	_, err = exec.LookPath("mkfs.btrfs")
	if err != nil {
		t.Skip("mkfs.btrfs not found, skipping test")
	}
	cmd := exec.Command("mkfs.btrfs", img)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("%q", cmd.Args)
		t.Log(string(out))
		t.Fatal(err)
	}

	// Mount
	mnt := img + ".mnt"
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
	defer syscall.Unlink(img)
	defer syscall.Unmount(mnt, 0)

	quirk := syscallcompat.DetectQuirks(mnt)
	if quirk != syscallcompat.QuirkBtrfsBrokenFalloc {
		t.Errorf("wrong quirk: %v", quirk)
	}
}
