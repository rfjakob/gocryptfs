package defaults

import (
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pkg/xattr"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// https://github.com/rfjakob/gocryptfs/issues/543
func TestCpA(t *testing.T) {
	fn1 := filepath.Join(test_helpers.TmpDir, t.Name())
	fn2 := filepath.Join(test_helpers.DefaultPlainDir, t.Name())

	rand.Seed(int64(time.Now().Nanosecond()))

	{
		// Need unrestricted umask
		old := syscall.Umask(000)
		defer syscall.Umask(old)
	}

	for i := 0; i < 10; i++ {
		// Random permissions (except owner read, which cp needs)
		var modeWant os.FileMode = os.FileMode(rand.Int31n(0777+1) | 0400)

		// Create file outside mount
		err := ioutil.WriteFile(fn1, nil, modeWant)
		if err != nil {
			t.Fatal(err)
		}
		// Verify perms (umask problems?)
		fi, err := os.Stat(fn1)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode() != modeWant {
			t.Errorf("ioutil.WriteFile created wrong permissions: want %o have %o", modeWant, fi.Mode())
		}

		// "cp -a" from outside to inside mount
		c := exec.Command("cp", "-a", fn1, fn2)
		c.Stderr = os.Stderr
		c.Stdout = os.Stdout
		err = c.Run()
		if err != nil {
			t.Fatal(err)
		}

		// Check perms
		fi, err = os.Stat(fn2)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode() != modeWant {
			t.Errorf("cp -a did not preserve permissions: want %o have %o", modeWant, fi.Mode())
		}

		syscall.Unlink(fn1)
		syscall.Unlink(fn2)
	}
}

func getfacl(fn string) (string, error) {
	c := exec.Command("getfacl", "-c", "--", fn)
	out, err := c.Output()
	return string(out), err
}

// https://github.com/rfjakob/gocryptfs/issues/543
func TestAcl543(t *testing.T) {
	fn1 := test_helpers.TmpDir + "/TestAcl543"
	fn2 := test_helpers.DefaultPlainDir + "/TestAcl543"

	var c *exec.Cmd

	var modeWant os.FileMode = 0777

	{
		// Need unrestricted umask
		old := syscall.Umask(000)
		defer syscall.Umask(old)
	}

	// Set acl on file outside gocryptfs mount
	err := ioutil.WriteFile(fn1, nil, modeWant)
	if err != nil {
		t.Fatal(err)
	}
	c = exec.Command("setfacl", "-m", "u:daemon:rwx", fn1)
	c.Stderr = os.Stderr
	c.Stdout = os.Stdout
	err = c.Run()
	if err != nil {
		t.Skip(err)
	}
	aclWant, err := getfacl(fn1)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(fn1)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != modeWant {
		t.Fatalf("mode changed from %o to %o", modeWant, fi.Mode())
	}

	// Set acl on file inside gocryptfs mount
	err = ioutil.WriteFile(fn2, nil, modeWant)
	if err != nil {
		t.Fatal(err)
	}
	c = exec.Command("setfacl", "-m", "u:daemon:rwx", fn2)
	c.Stderr = os.Stderr
	c.Stdout = os.Stdout
	err = c.Run()
	if err != nil {
		t.Fatal(err)
	}
	aclHave1, err := getfacl(fn1)
	if err != nil {
		t.Fatal(err)
	}
	if aclHave1 != aclWant {
		t.Error(aclHave1)
	}
	os.Remove(fn2)

	// "cp -a" from outside to inside mount
	c = exec.Command("cp", "-a", fn1, fn2)
	c.Stderr = os.Stderr
	c.Stdout = os.Stdout
	err = c.Run()
	if err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(fn2)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != modeWant {
		t.Errorf("cp -a did not preserve permissions: want %o have %o", modeWant, fi.Mode())
	}
	aclHave2, err := getfacl(fn2)
	if err != nil {
		t.Fatal(err)
	}
	if aclHave2 != aclWant {
		t.Errorf("cp -a did not preserve acl: %q", aclHave1)
	}
}

// Check that we handle zero-sized and undersized buffers correctly
func TestXattrOverflow(t *testing.T) {
	fn := filepath.Join(test_helpers.DefaultPlainDir, t.Name())
	ioutil.WriteFile(fn, nil, 0600)

	attr := "user.foo123"
	val := []byte("12341234")
	err := xattr.LSet(fn, attr, val)
	if err != nil {
		t.Skip(err)
	}

	// Getxattr
	sz, err := unix.Lgetxattr(fn, attr, nil)
	if err != nil {
		t.Error(err)
	}
	if sz != len(val) {
		t.Errorf("wrong sz: want %d have %d", len(val), sz)
	}
	_, err = unix.Lgetxattr(fn, attr, make([]byte, 1))
	if err != syscall.ERANGE {
		t.Error(err)
	}

	// Listxattr
	szWant, err := unix.Llistxattr(fn, make([]byte, 64*1024))
	if err != nil {
		t.Fatal(err)
	}
	sz, err = unix.Llistxattr(fn, nil)
	if err != nil {
		t.Error(err)
	}
	if sz != szWant {
		t.Errorf("wrong sz: want %d have %d", szWant, sz)
	}
	_, err = unix.Llistxattr(fn, make([]byte, 1))
	if err != syscall.ERANGE {
		t.Error(err)
	}
}
