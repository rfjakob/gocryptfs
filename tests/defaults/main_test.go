// Tests and benchmarks performed with default settings only.
package defaults

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestMain(m *testing.M) {
	test_helpers.ResetTmpDir(true)
	// TestZerokey() in tests/cli verifies that mounting with `-zerokey` is equivalent
	// to mounting with a config file with all-default options (just the masterkey
	// set to all-zero).
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
	// First FD is used for write and truncate.
	writeFd, err := os.Create(fn)
	if err != nil {
		t.Fatal(err)
	}
	defer writeFd.Close()
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
	defer readFd.Close()
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

// TestMvWarnings:
// When xattr support was introduced, mv threw warnings like these:
//
//	mv: preserving permissions for ‘b/x’: Operation not permitted
//
// because we returned EPERM when it tried to set system.posix_acl_access.
// Now we return EOPNOTSUPP and mv is happy.
func TestMvWarnings(t *testing.T) {
	fn := test_helpers.TmpDir + "/TestMvWarnings"
	err := ioutil.WriteFile(fn, nil, 0600)
	if err != nil {
		t.Fatalf("creating file failed: %v", err)
	}
	cmd := exec.Command("mv", fn, test_helpers.DefaultPlainDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Log(string(out))
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("Got warnings from mv:\n%s", string(out))
	}
}

// Check for this bug in symlink handling:
// $ ln -s /asd/asdasd/asdasd b/foo
// $ mv b/foo .
// mv: listing attributes of 'b/foo': No such file or directory
// strace shows:
// llistxattr("b/foo", NULL, 0) = -1 ENOENT (No such file or directory)
func TestMvWarningSymlink(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestMvWarningSymlink"
	err := os.Symlink("/foo/bar/baz", fn)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("mv", fn, test_helpers.TmpDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Log(string(out))
		if runtime.GOOS == "darwin" {
			t.Skip("mv on darwin chokes on broken symlinks, see https://github.com/rfjakob/gocryptfs/issues/349")
		}
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Log(strings.TrimSpace(string(out)))
		t.Fatal("Got warnings")
	}
}

// See TestMvWarnings.
func TestCpWarnings(t *testing.T) {
	fn := test_helpers.TmpDir + "/TestCpWarnings"
	err := ioutil.WriteFile(fn, []byte("foo"), 0600)
	if err != nil {
		t.Fatalf("creating file failed: %v", err)
	}
	cmd := exec.Command("cp", "-a", fn, test_helpers.DefaultPlainDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Log(string(out))
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("Got warnings from cp -a:\n%s", string(out))
	}
}

// TestSeekData tests that SEEK_DATA works
func TestSeekData(t *testing.T) {
	fn := filepath.Join(test_helpers.DefaultPlainDir, t.Name())
	f, err := os.Create(fn)
	if err != nil {
		t.Fatal(err)
	}
	var dataOffset int64 = 1024 * 1024 * 1024 // 1 GiB
	if _, err = f.Seek(dataOffset, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("foo")); err != nil {
		t.Fatal(err)
	}
	f.Close()

	f, err = os.Open(fn)
	if err != nil {
		t.Fatal(err)
	}
	off, err := f.Seek(1024*1024, unix.SEEK_DATA)
	if err != nil {
		t.Fatal(err)
	}
	if off < dataOffset-1024*1024 {
		t.Errorf("off=%d, expected=%d\n", off, dataOffset)
	}
	f.Close()
}

/*
TestMd5sumMaintainers tries to repro this interesting
bug that was seen during gocryptfs v2.0 development:

$ md5sum linux-3.0/MAINTAINERS linux-3.0/MAINTAINERS linux-3.0/MAINTAINERS linux-3.0/MAINTAINERS
279b6ab0491e7532132e8f32afe6c04d  linux-3.0/MAINTAINERS <-- WRONG!!!!
99cc9f0dfd86e63231b94edd43a43e02  linux-3.0/MAINTAINERS <-- correct
99cc9f0dfd86e63231b94edd43a43e02  linux-3.0/MAINTAINERS
99cc9f0dfd86e63231b94edd43a43e02  linux-3.0/MAINTAINERS

strace shows:

Bad
---
fstat(3, {st_mode=S_IFREG|0644, st_size=196745, ...}) = 0
read(3, "\n\tList of maintainers and how to"..., 32768) = 32768
read(3, "M:\tSylwester Nawrocki <s.nawrock"..., 32768) = 32768
read(3, "rs/scsi/eata*\n\nEATA ISA/EISA/PCI"..., 32768) = 32768
read(3, "F:\tDocumentation/isapnp.txt\nF:\td"..., 32768) = 32768
read(3, "hunkeey@googlemail.com>\nL:\tlinux"..., 32768) = 32768
read(3, "ach-spear3xx/\n\nSPEAR6XX MACHINE "..., 32768) = 32768 <--- WRONG LENGTH!!!
read(3, "", 32768)                      = 0
lseek(3, 0, SEEK_CUR)                   = 196608                <--- WRONG LENGTH!!!
close(3)                                = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x2), ...}) = 0
write(1, "279b6ab0491e7532132e8f32afe6c04d"..., 56279b6ab0491e7532132e8f32afe6c04d  linux-3.0/MAINTAINERS

Good
----
fstat(3, {st_mode=S_IFREG|0644, st_size=195191, ...}) = 0
read(3, "\n\tList of maintainers and how to"..., 32768) = 32768
read(3, "M:\tSylwester Nawrocki <s.nawrock"..., 32768) = 32768
read(3, "rs/scsi/eata*\n\nEATA ISA/EISA/PCI"..., 32768) = 32768
read(3, "F:\tDocumentation/isapnp.txt\nF:\td"..., 32768) = 32768
read(3, "hunkeey@googlemail.com>\nL:\tlinux"..., 32768) = 32768
read(3, "ach-spear3xx/\n\nSPEAR6XX MACHINE "..., 32768) = 31351
read(3, "", 4096)                       = 0
lseek(3, 0, SEEK_CUR)                   = 195191
close(3)                                = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x2), ...}) = 0
write(1, "99cc9f0dfd86e63231b94edd43a43e02"..., 5699cc9f0dfd86e63231b94edd43a43e02  linux-3.0/MAINTAINERS
*/
func TestMd5sumMaintainers(t *testing.T) {
	fn := filepath.Join(test_helpers.DefaultPlainDir, t.Name())
	f, err := os.Create(fn)
	if err != nil {
		t.Fatal(err)
	}
	// Size of the MAINTAINERS file = 195191
	const sizeWant = 195191
	content := make([]byte, sizeWant)
	_, err = f.Write(content)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Remount to clear the linux kernel attr cache
	// (otherwise we would have to wait 2 seconds for the entry to expire)
	test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
	test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, "-zerokey")

	cmd := exec.Command("md5sum", fn, fn, fn, fn)
	out2, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	out := string(out2)

	// 195191 zero bytes have this md5sum
	const md5Want = "b99bf6917f688068acd49126f3b1b005"

	n := strings.Count(out, md5Want)
	if n != 4 {
		t.Errorf("found %d instead of %d instances of %q", n, 4, md5Want)
		t.Logf("full output:\n%s", out)
	}
}

func TestMaxlen(t *testing.T) {
	workDir := filepath.Join(test_helpers.DefaultPlainDir, t.Name())
	if err := os.Mkdir(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("../../contrib/maxlen.bash", workDir)
	cmd.Env = []string{"QUICK=1"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Log(string(out))
		t.Fatal(err)
	}
	want := `
  Maximum filename length: 255
  Maximum path length with 100 chars per subdir: 4095
`
	if !strings.HasSuffix(string(out), want) {
		t.Errorf("wrong output: %s", string(out))
	}
}

func TestFsync(t *testing.T) {
	fileName := test_helpers.DefaultPlainDir + "/" + t.Name() + ".file"
	fileFD, err := syscall.Open(fileName, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fileFD)
	dirName := test_helpers.DefaultPlainDir + "/" + t.Name() + ".dir"
	if err := os.Mkdir(dirName, 0700); err != nil {
		t.Fatal(err)
	}
	dirFD, err := syscall.Open(dirName, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(dirFD)

	err = syscall.Fsync(dirFD)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Fsync(fileFD)
	if err != nil {
		t.Fatal(err)
	}
}

// force_owner was broken by the v2.0 rewrite:
// The owner was only forced for GETATTR, but not for CREATE, LOOKUP, MKNOD.
//
// https://github.com/rfjakob/gocryptfs/issues/609
// https://github.com/rfjakob/gocryptfs/pull/610
// https://github.com/rfjakob/gocryptfs/issues/629
func TestForceOwner(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	os.Chmod(cDir, 0777) // Mount needs to be accessible for us
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-force_owner=1234:1234", "-extpass=echo test")
	defer test_helpers.UnmountPanic(pDir)

	// We need an unrestricted umask
	oldmask := syscall.Umask(0)
	defer syscall.Umask(oldmask)

	foo := pDir + "/foo"

	// In the answer to a FUSE CREATE, gocryptfs sends file information including
	// the owner. This is cached by the kernel and will be used for the next
	// stat() call.
	fd, err := syscall.Open(foo, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_EXCL, 0666)
	if err != nil {
		t.Fatal(err)
	}
	syscall.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Stat(foo, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != 1234 || st.Gid != 1234 {
		t.Errorf("CREATE returned uid or gid != 1234: %#v", st)
	}

	// We can clear the kernel stat() cache by writing to the file
	fd, err = syscall.Open(foo, syscall.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syscall.Write(fd, []byte("hello world")); err != nil {
		t.Fatal(err)
	}
	syscall.Close(fd)

	// This stat() triggers a new GETATTR
	if err := syscall.Stat(foo, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != 1234 || st.Gid != 1234 {
		t.Errorf("GETATTR returned uid or gid != 1234: %#v", st)
	}

	// Test MKNOD
	sock := pDir + "/sock"
	if err := syscall.Mknod(sock, syscall.S_IFSOCK|0600, 0); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(sock, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != 1234 || st.Gid != 1234 {
		t.Errorf("MKNOD returned uid or gid != 1234: %#v", st)
	}

	// Remount to clear cache
	test_helpers.UnmountPanic(pDir)
	test_helpers.MountOrFatal(t, cDir, pDir, "-force_owner=1234:1234", "-extpass=echo test")

	// This stat() triggers a new LOOKUP
	if err := syscall.Stat(foo, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != 1234 || st.Gid != 1234 {
		t.Errorf("LOOKUP returned uid or gid != 1234: %#v", st)
	}
}
