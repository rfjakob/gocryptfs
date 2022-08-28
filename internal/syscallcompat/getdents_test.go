//go:build linux
// +build linux

package syscallcompat

import (
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"
)

var emulate = false

func TestGetdents(t *testing.T) {
	t.Logf("testing native getdents")
	testGetdents(t)
	t.Logf("testing emulateGetdents")
	emulate = true
	testGetdents(t)
}

// skipOnGccGo skips the emulateGetdents test when we are
// running linux and were compiled with gccgo. The test is known to fail
// (https://github.com/rfjakob/gocryptfs/issues/201), but getdents emulation
// is not used on linux, so let's skip the test and ignore the failure.
func skipOnGccGo(t *testing.T) {
	if !emulate || runtime.GOOS != "linux" {
		return
	}
	// runtime.Version() output...
	// on go:    go1.9.2
	// on gccgo: go1.8.1 gccgo (GCC) 7.2.1 20170915 (Red Hat 7.2.1-2)
	v := runtime.Version()
	if strings.Contains(v, "gccgo") {
		t.Skipf("test is known-broken on gccgo")
	}
}

func testGetdents(t *testing.T) {
	getdentsUnderTest := getdents
	if emulate {
		getdentsUnderTest = emulateGetdents
	}
	// Fill a directory with filenames of length 1 ... 255
	testDir, err := ioutil.TempDir(tmpDir, "TestGetdents")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= unix.NAME_MAX; i++ {
		n := strings.Repeat("x", i)
		err = ioutil.WriteFile(testDir+"/"+n, nil, 0600)
		if err != nil {
			t.Fatal(err)
		}
	}
	// "/", "/dev" and "/proc/self" are good test cases because they contain
	// many different file types (block and char devices, symlinks,
	// mountpoints).
	dirs := []string{testDir, "/", "/dev", "/proc/self"}
	for _, dir := range dirs {
		// Read directory using stdlib Readdir()
		fd, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer fd.Close()
		readdirEntries, err := fd.Readdir(0)
		if err != nil {
			t.Fatal(err)
		}
		readdirMap := make(map[string]*syscall.Stat_t)
		for _, v := range readdirEntries {
			readdirMap[v.Name()] = fuse.ToStatT(v)
		}
		// Read using our Getdents() implementation
		_, err = fd.Seek(0, 0) // Rewind directory
		if err != nil {
			t.Fatal(err)
		}
		getdentsEntries, special, err := getdentsUnderTest(int(fd.Fd()))
		if err != nil {
			t.Log(err)
			skipOnGccGo(t)
			t.FailNow()
		}
		getdentsMap := make(map[string]fuse.DirEntry)
		for _, v := range getdentsEntries {
			getdentsMap[v.Name] = v
		}
		// Compare results
		if len(getdentsEntries) != len(readdirEntries) {
			t.Fatalf("len(getdentsEntries)=%d, len(readdirEntries)=%d",
				len(getdentsEntries), len(readdirEntries))
		}
		for name := range readdirMap {
			g := getdentsMap[name]
			r := readdirMap[name]
			rTyp := r.Mode & syscall.S_IFMT
			if g.Mode != rTyp {
				t.Errorf("%q: g.Mode=%#o, r.Mode=%#o", name, g.Mode, rTyp)
			}
			if g.Ino != r.Ino {
				// The inode number of a directory that is reported by stat
				// and getdents is different when it is a mountpoint. Only
				// throw an error when we are NOT looking at a directory.
				if g.Mode != syscall.S_IFDIR {
					t.Errorf("%s: g.Ino=%d, r.Ino=%d", name, g.Ino, r.Ino)
				}
			}
		}
		if len(special) != 2 {
			t.Error(special)
		}
		if !(special[0].Name == "." && special[1].Name == ".." ||
			special[1].Name == "." && special[0].Name == "..") {
			t.Error(special)
		}
		for _, v := range special {
			if v.Ino == 0 {
				t.Error(v)
			}
			if v.Mode != syscall.S_IFDIR {
				t.Error(v)
			}
		}
	}
}
