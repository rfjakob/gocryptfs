package test_helpers

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/internal/ctlsock"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

// TmpDir will be created inside this directory
const testParentDir = "/tmp/gocryptfs-test-parent"

// GocryptfsBinary is the assumed path to the gocryptfs build.
const GocryptfsBinary = "../../gocryptfs"

// TmpDir is a unique temporary directory. "go test" runs package tests in parallel. We create a
// unique TmpDir in init() so the tests do not interfere.
var TmpDir string

// DefaultPlainDir is TmpDir + "/default-plain"
var DefaultPlainDir string

// DefaultCipherDir is TmpDir + "/default-cipher"
var DefaultCipherDir string

func init() {
	os.MkdirAll(testParentDir, 0700)
	var err error
	TmpDir, err = ioutil.TempDir(testParentDir, "")
	if err != nil {
		panic(err)
	}
	DefaultPlainDir = TmpDir + "/default-plain"
	DefaultCipherDir = TmpDir + "/default-cipher"
}

// ResetTmpDir deletes TmpDir, create new dir tree:
//
// TmpDir
// |-- DefaultPlainDir
// *-- DefaultCipherDir
//     *-- gocryptfs.diriv
func ResetTmpDir(createDirIV bool) {
	// Try to unmount and delete everything
	entries, err := ioutil.ReadDir(TmpDir)
	if err == nil {
		for _, e := range entries {
			d := filepath.Join(TmpDir, e.Name())
			err = os.Remove(d)
			if err != nil {
				pe := err.(*os.PathError)
				if pe.Err == syscall.EBUSY {
					if testing.Verbose() {
						fmt.Printf("Remove failed: %v. Maybe still mounted?\n", pe)
					}
					err = UnmountErr(d)
					if err != nil {
						panic(err)
					}
				} else if pe.Err != syscall.ENOTEMPTY {
					panic("Unhandled error: " + pe.Err.Error())
				}
				err = os.RemoveAll(d)
				if err != nil {
					panic(err)
				}
			}
		}
	}
	err = os.Mkdir(DefaultPlainDir, 0700)
	if err != nil {
		panic(err)
	}
	err = os.Mkdir(DefaultCipherDir, 0700)
	if err != nil {
		panic(err)
	}
	if createDirIV {
		err = nametransform.WriteDirIV(DefaultCipherDir)
		if err != nil {
			panic(err)
		}
	}
}

// InitFS calls "gocryptfs -init" on a new directory in TmpDir, passing
// "extraArgs" in addition to useful defaults.
//
// The returned cipherdir has NO trailing slash.
func InitFS(t *testing.T, extraArgs ...string) string {
	dir, err := ioutil.TempDir(TmpDir, "")
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-q", "-init", "-extpass", "echo test", "-scryptn=10"}
	args = append(args, extraArgs...)
	args = append(args, dir)

	cmd := exec.Command(GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		t.Fatalf("InitFS with args %v failed: %v", args, err)
	}

	return dir
}

// Mount CIPHERDIR "c" on PLAINDIR "p"
// Creates "p" if it does not exist.
func Mount(c string, p string, showOutput bool, extraArgs ...string) error {
	var args []string
	args = append(args, "-q", "-wpanic", "-nosyslog")
	args = append(args, extraArgs...)
	//args = append(args, "-fusedebug")
	//args = append(args, "-d")
	args = append(args, c)
	args = append(args, p)

	if _, err := os.Stat(p); err != nil {
		err = os.Mkdir(p, 0777)
		if err != nil {
			return err
		}
	}

	cmd := exec.Command(GocryptfsBinary, args...)
	if showOutput {
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
	}

	return cmd.Run()
}

// MountOrExit calls Mount() and exits on failure.
func MountOrExit(c string, p string, extraArgs ...string) {
	err := Mount(c, p, true, extraArgs...)
	if err != nil {
		fmt.Printf("mount failed: %v", err)
		os.Exit(1)
	}
}

// MountOrFatal calls Mount() and calls t.Fatal() on failure.
func MountOrFatal(t *testing.T, c string, p string, extraArgs ...string) {
	err := Mount(c, p, true, extraArgs...)
	if err != nil {
		t.Fatal(fmt.Errorf("mount failed: %v", err))
	}
}

// UnmountPanic tries to umount "dir" and panics on error.
func UnmountPanic(dir string) {
	err := UnmountErr(dir)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
}

// UnmountErr tries to unmount "dir" and returns the resulting error.
func UnmountErr(dir string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("umount", dir)
	} else {
		cmd = exec.Command("fusermount", "-u", "-z", dir)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Md5fn returns an md5 string for file "filename"
func Md5fn(filename string) string {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("ReadFile: %v\n", err)
		return ""
	}
	return Md5hex(buf)
}

// Md5hex returns an md5 string for "buf"
func Md5hex(buf []byte) string {
	rawHash := md5.Sum(buf)
	hash := hex.EncodeToString(rawHash[:])
	return hash
}

// VerifySize checks that the file size equals "want". This checks:
// 1) Size reported by Stat()
// 2) Number of bytes returned when reading the whole file
func VerifySize(t *testing.T, path string, want int) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		t.Errorf("ReadFile failed: %v", err)
	} else if len(buf) != want {
		t.Errorf("wrong read size: got=%d want=%d", len(buf), want)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Errorf("Stat failed: %v", err)
	} else if fi.Size() != int64(want) {
		t.Errorf("wrong stat file size, got=%d want=%d", fi.Size(), want)
	}
}

// TestMkdirRmdir creates and deletes a directory
func TestMkdirRmdir(t *testing.T, plainDir string) {
	dir := plainDir + "/dir1"
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Error(err)
		return
	}
	err = syscall.Rmdir(dir)
	if err != nil {
		t.Error(err)
		return
	}
	// Removing a non-empty dir should fail with ENOTEMPTY
	if os.Mkdir(dir, 0777) != nil {
		t.Error(err)
		return
	}
	f, err := os.Create(dir + "/file")
	if err != nil {
		t.Error(err)
		return
	}
	f.Close()
	err = syscall.Rmdir(dir)
	errno := err.(syscall.Errno)
	if errno != syscall.ENOTEMPTY {
		t.Errorf("Should have gotten ENOTEMPTY, go %v", errno)
	}
	if syscall.Unlink(dir+"/file") != nil {
		t.Error(err)
		return
	}
	if syscall.Rmdir(dir) != nil {
		t.Error(err)
		return
	}
	// We should also be able to remove a directory we do not have permissions to
	// read or write
	err = os.Mkdir(dir, 0000)
	if err != nil {
		t.Error(err)
		return
	}
	err = syscall.Rmdir(dir)
	if err != nil {
		// Make sure the directory can cleaned up by the next test run
		os.Chmod(dir, 0700)
		t.Error(err)
		return
	}
}

// TestRename creates and renames a file
func TestRename(t *testing.T, plainDir string) {
	file1 := plainDir + "/rename1"
	file2 := plainDir + "/rename2"
	err := ioutil.WriteFile(file1, []byte("content"), 0777)
	if err != nil {
		t.Error(err)
		return
	}
	err = syscall.Rename(file1, file2)
	if err != nil {
		t.Error(err)
		return
	}
	syscall.Unlink(file2)
}

// VerifyExistence checks in 3 ways that "path" exists:
// stat, open, readdir
func VerifyExistence(path string) bool {
	// Check that file can be stated
	_, err := os.Stat(path)
	if err != nil {
		//t.Log(err)
		return false
	}
	// Check that file can be opened
	fd, err := os.Open(path)
	if err != nil {
		//t.Log(err)
		return false
	}
	fd.Close()
	// Check that file shows up in directory listing
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	fi, err := ioutil.ReadDir(dir)
	if err != nil {
		//t.Log(err)
		return false
	}
	for _, i := range fi {
		if i.Name() == name {
			return true
		}
	}
	return false
}

// Du returns the disk usage of the file "fd" points to, in bytes.
// Same as "du --block-size=1".
func Du(t *testing.T, fd int) (nBytes int64) {
	var st syscall.Stat_t
	err := syscall.Fstat(fd, &st)
	if err != nil {
		t.Fatal(err)
	}
	// st.Blocks = number of 512-byte blocks
	return st.Blocks * 512
}

// QueryCtlSock sends a request to the control socket at "socketPath" and
// returns the response.
func QueryCtlSock(t *testing.T, socketPath string, req ctlsock.RequestStruct) (response ctlsock.ResponseStruct) {
	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	msg, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write(msg)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2*syscall.PathMax)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf = buf[:n]
	json.Unmarshal(buf, &response)
	return response
}
