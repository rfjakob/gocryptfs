package test_helpers

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// TmpDir will be created inside this directory, set in init() to
// $TMPDIR/gocryptfs-test-parent .
var testParentDir = ""

// GocryptfsBinary is the assumed path to the gocryptfs build.
const GocryptfsBinary = "../../gocryptfs"

// UnmountScript is the fusermount/umount compatibility wrapper script
const UnmountScript = "../../tests/fuse-unmount.bash"

// X255 contains 255 uppercase "X". This can be used as a maximum-length filename.
var X255 string

// TmpDir is a unique temporary directory. "go test" runs package tests in parallel. We create a
// unique TmpDir in init() so the tests do not interfere.
var TmpDir string

// DefaultPlainDir is TmpDir + "/default-plain"
var DefaultPlainDir string

// DefaultCipherDir is TmpDir + "/default-cipher"
var DefaultCipherDir string

func init() {
	doInit()
}

func doInit() {
	X255 = string(bytes.Repeat([]byte("X"), 255))
	MountInfo = make(map[string]mountInfo)
	// Something like /tmp/gocryptfs-test-parent-1234
	testParentDir = fmt.Sprintf("%s/gocryptfs-test-parent-%d", os.TempDir(), os.Getuid())
	os.MkdirAll(testParentDir, 0755)
	if !isExt4(testParentDir) {
		fmt.Printf("test_helpers: warning: testParentDir %q does not reside on ext4, we will miss failures caused by ino reuse\n", testParentDir)
	}
	var err error
	TmpDir, err = ioutil.TempDir(testParentDir, "")
	if err != nil {
		panic(err)
	}
	// Open permissions for the allow_other tests
	os.Chmod(TmpDir, 0755)
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
	err = os.Mkdir(DefaultPlainDir, 0755)
	if err != nil {
		panic(err)
	}
	err = os.Mkdir(DefaultCipherDir, 0755)
	if err != nil {
		panic(err)
	}
	if createDirIV {
		// Open cipherdir (following symlinks)
		dirfd, err := syscall.Open(DefaultCipherDir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err == nil {
			err = nametransform.WriteDirIVAt(dirfd)
			syscall.Close(dirfd)
		}
		if err != nil {
			panic(err)
		}
	}
}

// isExt4 finds out if `path` resides on an ext4 filesystem, as reported by
// statfs.
func isExt4(path string) bool {
	// From man statfs
	const EXT4_SUPER_MAGIC = 0xef53

	var fs syscall.Statfs_t
	err := syscall.Statfs(path, &fs)
	if err != nil {
		return false
	}
	if fs.Type == EXT4_SUPER_MAGIC {
		return true
	}
	return false
}

// InitFS creates a new empty cipherdir and calls
//
//     gocryptfs -q -init -extpass "echo test" -scryptn=10 $extraArgs $cipherdir
//
// It returns cipherdir without a trailing slash.
//
// If t is set, t.Fatal() is called on error, log.Panic() otherwise.
func InitFS(t *testing.T, extraArgs ...string) string {
	prefix := "x."
	if t != nil {
		prefix = t.Name() + "."
	}
	dir, err := ioutil.TempDir(TmpDir, prefix)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		} else {
			log.Panic(err)
		}
	}
	args := []string{"-q", "-init", "-extpass", "echo test", "-scryptn=10"}
	args = append(args, extraArgs...)
	args = append(args, dir)

	cmd := exec.Command(GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		if t != nil {
			t.Fatalf("InitFS with args %q failed: %v", args, err)
		} else {
			log.Panic(err)
		}
	}

	return dir
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
// 1) Number of bytes returned when reading the whole file
// 2) Size reported by Stat()
// 3) Size reported by Fstat()
func VerifySize(t *testing.T, path string, want int) {
	// Read whole file
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		t.Errorf("ReadFile failed: %v", err)
	} else if len(buf) != want {
		t.Errorf("wrong read size: got=%d want=%d", len(buf), want)
	}
	// Stat()
	var st syscall.Stat_t
	err = syscall.Stat(path, &st)
	if err != nil {
		t.Errorf("Stat failed: %v", err)
	} else if st.Size != int64(want) {
		t.Errorf("wrong stat file size, got=%d want=%d", st.Size, want)
	}
	// Fstat()
	fd, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	var st2 syscall.Stat_t
	err = syscall.Fstat(int(fd.Fd()), &st2)
	if err != nil {
		t.Fatal(err)
	}
	if st2.Size != int64(want) {
		t.Errorf("wrong fstat file size, got=%d want=%d", st2.Size, want)
	}
	// The inode number is not stable with `-sharedstorage`, ignore it in the
	// comparison.
	st.Ino = 0
	st2.Ino = 0
	if st != st2 {
		t.Logf("Stat vs Fstat mismatch:\nst= %#v\nst2=%#v", st, st2)
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
	// Create a directory and put a file in it
	// Trying to rmdir it should fail with ENOTEMPTY
	err = os.Mkdir(dir, 0777)
	if err != nil {
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
		t.Errorf("Should have gotten ENOTEMPTY, got %v", errno)
	}
	err = syscall.Unlink(dir + "/file")
	if err != nil {
		var st syscall.Stat_t
		syscall.Stat(dir, &st)
		t.Errorf("err=%v mode=%0o", err, st.Mode)
		return
	}
	err = syscall.Rmdir(dir)
	if err != nil {
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
		t.Errorf("Rename: %v", err)
		return
	}
	syscall.Unlink(file2)
}

// VerifyExistence checks in 3 ways that "path" exists:
// stat, open, readdir. Returns true if the path exists, false otherwise.
// Panics if the result is inconsistent.
func VerifyExistence(t *testing.T, path string) bool {
	t.Helper()
	// Check if file can be stat()ed
	stat := true
	fi, err := os.Stat(path)
	if err != nil {
		stat = false
	}
	// Check if file can be opened
	open := true
	fd, err := os.Open(path)
	if err != nil {
		open = false
	}
	fd.Close()
	// Check if file shows up in directory listing
	readdir := false
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	d, err := os.Open(dir)
	if err != nil && open {
		t.Errorf("VerifyExistence: we can open the file but not the parent dir!? err=%v", err)
	} else if err == nil {
		defer d.Close()
		listing, err := d.Readdirnames(0)
		if stat && fi.IsDir() && err != nil {
			t.Errorf("VerifyExistence: It's a directory, but readdirnames failed: %v", err)
		}
		for _, entry := range listing {
			if entry == name {
				readdir = true
			}
		}
	}
	// If the result is consistent, return it.
	if stat == open && open == readdir {
		return stat
	}
	t.Errorf("VerifyExistence: inconsistent result on %q: stat=%v open=%v readdir=%v, path=%q", name, stat, open, readdir, path)
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
func QueryCtlSock(t *testing.T, socketPath string, req ctlsock.RequestStruct) ctlsock.ResponseStruct {
	c, err := ctlsock.New(socketPath)
	if err != nil {
		// Connecting to the socket failed already. This is fatal.
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Query(&req)
	if err != nil {
		// If we got a response, try to extract it. This is not fatal here
		// as the tests may expect error responses.
		if resp2, ok := err.(*ctlsock.ResponseStruct); ok {
			return *resp2
		}
		// Another error means that we did not even get a response. This is fatal.
		t.Fatal(err)
	}
	return *resp
}

// ExtractCmdExitCode extracts the exit code from an error value that was
// returned from exec / cmd.Run()
func ExtractCmdExitCode(err error) int {
	if err == nil {
		return 0
	}
	// OMG this is convoluted
	if err2, ok := err.(*exec.ExitError); ok {
		return err2.Sys().(syscall.WaitStatus).ExitStatus()
	}
	if err2, ok := err.(*os.PathError); ok {
		return int(err2.Err.(syscall.Errno))
	}
	log.Panicf("could not decode error %#v", err)
	return 0
}
