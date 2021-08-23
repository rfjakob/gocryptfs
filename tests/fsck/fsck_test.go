package fsck

import (
	"encoding/base64"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/xattr"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func dec64(in string) (out []byte) {
	out, err := base64.RawURLEncoding.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return out
}

func TestBrokenFsV14(t *testing.T) {
	// git does not save extended attributes, so we apply them here.
	// xattr_good
	xattr.Set("broken_fs_v1.4/6nGs4Ugr3EAHd0KzkyLZ-Q",
		"user.gocryptfs.0a5e7yWl0SGUGeWB0Sy2Kg",
		dec64("hxnZvXSkDicfwVS9w4r1yYkFF61Qou6NaL-VhObYEdu6kuM"))
	// xattr_corrupt_name
	xattr.Set("broken_fs_v1.4/CMyUifVTjW5fsgXonWBT_RDkvLkdGrLttkZ45T3Oi3A",
		"user.gocryptfs.0a5e7yWl0SGUGeWB0Sy2K0",
		dec64("QHUMDTgbnl8Sv_A2dFQic_G2vN4_gmDna3651JAhF7OZ-YI"))
	// xattr_corrupt_value
	xattr.Set("broken_fs_v1.4/b00sbnGXGToadr01GHZaYQn8tjyRhe1OXNBZoQtMlcQ",
		"user.gocryptfs.0a5e7yWl0SGUGeWB0Sy2Kg",
		dec64("A0hvCePeKpL8bCpijhDKtf7cIijXYQsPnEbNJ84M2ONW0dd"))

	cmd := exec.Command(test_helpers.GocryptfsBinary, "-fsck", "-extpass", "echo test", "broken_fs_v1.4")
	outBin, err := cmd.CombinedOutput()
	out := string(outBin)
	t.Log(out)
	code := test_helpers.ExtractCmdExitCode(err)
	if code != exitcodes.FsckErrors {
		t.Errorf("wrong exit code, have=%d want=%d", code, exitcodes.FsckErrors)
	}
}

func TestExampleFses(t *testing.T) {
	dirfd, err := os.Open("../example_filesystems")
	if err != nil {
		t.Fatal(err)
	}
	var fsNames []string
	entries, err := dirfd.Readdir(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.Contains(e.Name(), "reverse") {
			continue
		}
		if e.Name() == "content" {
			continue
		}
		fsNames = append(fsNames, e.Name())
	}
	for _, n := range fsNames {
		t.Logf("Checking %q", n)
		path := "../example_filesystems/" + n
		cmd := exec.Command(test_helpers.GocryptfsBinary, "-fsck", "-extpass", "echo test", path)
		outBin, err := cmd.CombinedOutput()
		out := string(outBin)
		code := test_helpers.ExtractCmdExitCode(err)
		if code == exitcodes.DeprecatedFS {
			continue
		}
		if code != 0 {
			t.Log(out)
			t.Errorf("fsck returned code %d but fs should be clean", code)
		}
	}
	dirfd.Close()
}

// TestTerabyteFile verifies that fsck does something intelligent when it hits
// a 1-terabyte sparse file (trying to read the whole file is not intelligent).
func TestTerabyteFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Only linux supports SEEK_DATA")
	}
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	defer test_helpers.UnmountErr(pDir)
	veryBigFile := pDir + "/veryBigFile"
	fd, err := os.Create(veryBigFile)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	var oneTiB int64 = 1024 * 1024 * 1024 * 1024
	_, err = fd.WriteAt([]byte("foobar"), oneTiB)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("size=%d, running fsck", fi.Size())
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-fsck", "-extpass", "echo test", cDir)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Start()
	timer := time.AfterFunc(10*time.Second, func() {
		t.Error("timeout, sending SIGINT")
		syscall.Kill(cmd.Process.Pid, syscall.SIGINT)
	})
	cmd.Wait()
	timer.Stop()
}
