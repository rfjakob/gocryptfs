// Tests and benchmarks performed with default settings only.
package defaults

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/ctlsock"
	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func TestMain(m *testing.M) {
	test_helpers.ResetTmpDir(true)
	test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, "-zerokey")
	r := m.Run()
	test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
	os.Exit(r)
}

// Test that we get the right timestamp when extracting a tarball.
func Test1980Tar(t *testing.T) {
	c := exec.Command("tar", "xzf", "1980.tar.gz", "-C", test_helpers.DefaultPlainDir)
	c.Stderr = os.Stderr
	c.Stdout = os.Stdout
	err := c.Run()
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(test_helpers.DefaultPlainDir + "/1980.txt")
	if err != nil {
		t.Fatal(err)
	}
	m := fi.ModTime().Unix()
	if m != 315619323 {
		t.Errorf("Wrong mtime: %d", m)
	}
}

func TestCtlSock(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	sock := cDir + ".sock"
	test_helpers.MountOrFatal(t, cDir, pDir, "-ctlsock="+sock, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(pDir)
	req := ctlsock.RequestStruct{
		EncryptPath: "foobar",
	}
	response := test_helpers.QueryCtlSock(t, sock, req)
	if response.Result == "" || response.ErrNo != 0 {
		t.Errorf("got an error reply: %+v", response)
	}
	req.EncryptPath = "not-existing-dir/xyz"
	response = test_helpers.QueryCtlSock(t, sock, req)
	if response.ErrNo != int32(syscall.ENOENT) || response.Result != "" {
		t.Errorf("incorrect error handling: %+v", response)
	}
}
