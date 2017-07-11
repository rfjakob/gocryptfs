// Tests and benchmarks performed with default settings only.
package defaults

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"

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

// In gocryptfs before v1.2, the file header was only read once for each
// open. But truncating a file to zero will generate a new random file ID.
// The sequence below caused an I/O error to be returned.
func TestOpenTruncateRead(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestTruncateWrite"
	// First FD is used for write and trucate.
	writeFd, err := os.Create(fn)
	if err != nil {
		t.Fatal(err)
	}
	abc := []byte("abc")
	_, err = writeFd.WriteAt(abc, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Second FD is just for reading.
	readFd, err := os.Open(fn)
	if err != nil {
		t.Fatal(err)
	}
	content := make([]byte, 3)
	_, err = readFd.ReadAt(content, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, abc) {
		t.Fatalf("wrong content: %s", string(content))
	}
	// Truncate to zero to generate a new file ID and write new content.
	err = writeFd.Truncate(0)
	if err != nil {
		t.Fatal(err)
	}
	xyz := []byte("xyz")
	_, err = writeFd.WriteAt(xyz, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Try to read from the other FD.
	_, err = readFd.ReadAt(content, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, xyz) {
		t.Fatalf("wrong content: %s", string(content))
	}
}

// TestWORead tries to read from a write-only FD.
func TestWORead(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestWORead"
	fd, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	buf := make([]byte, 10)
	_, err = fd.Read(buf)
	if err == nil {
		t.Error("Reading from write-only file should fail, but did not")
	}
}

// xfstests generic/124 triggers this warning:
// cipherSize 18 == header size: interrupted write?
// This test reproduces the problem.
func TestXfs124(t *testing.T) {
	// GOMAXPROCS=8 and N=5000 seem to reliably trigger the problem. With N=1000,
	// the test passes sometimes.
	runtime.GOMAXPROCS(8)
	N := 5000

	fn := test_helpers.DefaultPlainDir + "/TestXfs124"
	fd, err := os.Create(fn)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		buf := make([]byte, 10)
		var err2 error
		for i := 0; i < N; i++ {
			err2 = fd.Truncate(0)
			if err2 != nil {
				panic(err2)
			}
			_, err2 = fd.WriteAt(buf, 0)
			if err2 != nil {
				panic(err2)
			}
		}
		wg.Done()
	}()

	fd2, err := os.Open(fn)
	if err != nil {
		t.Fatal(err)
	}
	defer fd2.Close()

	go func() {
		buf := make([]byte, 10)
		var err3 error
		for i := 0; i < N; i++ {
			_, err3 = fd2.ReadAt(buf, 0)
			if err3 == io.EOF {
				continue
			}
			if err3 != nil {
				panic(err3)
			}
		}
		wg.Done()
	}()

	wg.Wait()
}

func TestWrite0200File(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestWrite0200File"
	err := ioutil.WriteFile(fn, nil, 0200)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	fd, err := os.OpenFile(fn, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	perms := fi.Mode().Perm()
	if perms != 0200 {
		t.Fatal("wrong initial permissions")
	}
	defer fd.Close()
	_, err = fd.Write(make([]byte, 10))
	if err != nil {
		t.Fatal(err)
	}
	perms = fi.Mode().Perm()
	if perms != 0200 {
		t.Fatal("wrong restored permissions")
	}
}
