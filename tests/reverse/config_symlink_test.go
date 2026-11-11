package reverse_test

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestConfigSymlink verifies that gocryptfs.conf in the reverse view does
// not follow a symlink at .gocryptfs.reverse.conf. The config file is passed
// through unencrypted, so following the symlink would let anybody with write
// access to the backing directory read arbitrary files (like /etc/shadow when
// gocryptfs runs as root) through the mount.
func TestConfigSymlink(t *testing.T) {
	backingDir, err := os.MkdirTemp(test_helpers.TmpDir, t.Name()+".")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-q", "-init", "-reverse",
		"-extpass", "echo test", "-scryptn=10", backingDir)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	mnt := backingDir + ".mnt"
	// -wpanic=false because gocryptfs warns about the symlink and the FIFO
	test_helpers.MountOrFatal(t, backingDir, mnt, "-reverse", "-extpass", "echo test", "-wpanic=false")
	defer test_helpers.UnmountPanic(mnt)

	conf := backingDir + "/.gocryptfs.reverse.conf"
	mntConf := mnt + "/gocryptfs.conf"
	// Sanity check: the regular config file is visible
	if _, err := os.Stat(mntConf); err != nil {
		t.Fatal(err)
	}

	// Replace .gocryptfs.reverse.conf with a symlink to a secret file
	const secretContent = "SECRET-dd0eea2a"
	secret := backingDir + ".secret"
	if err := os.WriteFile(secret, []byte(secretContent), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(conf, conf+".bak"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, conf); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(mntConf)
	if strings.Contains(string(data), secretContent) {
		t.Fatalf("symlink was followed, secret leaked: %q", data)
	}
	if err == nil {
		t.Errorf("reading %s should have failed", mntConf)
	}

	// Replace it with a FIFO. Opening it must neither hang nor succeed.
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(conf, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := os.ReadFile(mntConf)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("reading %s (FIFO) should have failed", mntConf)
		}
	case <-time.After(5 * time.Second):
		// Unblock the hung open so that unmount can succeed
		if f, err := os.OpenFile(conf, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
		t.Fatalf("reading %s (FIFO) hung", mntConf)
	}

	// Restore the regular file. It must be visible again.
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(conf+".bak", conf); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(mntConf)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("empty config file")
	}
}
