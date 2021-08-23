package cli

import (
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestZerokey verifies that `gocryptfs -zerokey` uses the same options as
// `gocryptfs -init`.
func TestZerokey(t *testing.T) {
	// Create FS
	dir := test_helpers.InitFS(t)

	// Change masterkey to all-zero using password change
	args := []string{"-q", "-passwd", "-masterkey",
		"00000000-00000000-00000000-00000000-00000000-00000000-00000000-00000000"}
	args = append(args, dir)
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	p, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Start()
	if err != nil {
		t.Error(err)
	}
	// New password = old password
	p.Write([]byte("test\n"))
	p.Close()
	err = cmd.Wait()
	if err != nil {
		t.Error(err)
	}

	// Add content
	mnt := dir + ".mnt"
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass", "echo test")
	file1 := mnt + "/file1"
	err = ioutil.WriteFile(file1, []byte("somecontent"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.UnmountPanic(mnt)

	// Mount using -zerokey and verify we get the same result
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass", "echo test")
	content, err := ioutil.ReadFile(file1)
	if err != nil {
		t.Error(err)
	} else if string(content) != "somecontent" {
		t.Errorf("wrong content: %q", string(content))
	}
	test_helpers.UnmountPanic(mnt)
}
