// +build linux

package syscallcompat

import (
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"
)

var getdentsUnderTest = getdents

func TestGetdents(t *testing.T) {
	t.Logf("testing native getdents")
	testGetdents(t)
	t.Logf("testing emulateGetdents")
	getdentsUnderTest = emulateGetdents
	testGetdents(t)
}

func testGetdents(t *testing.T) {
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
		getdentsEntries, err := getdentsUnderTest(int(fd.Fd()))
		if err != nil {
			t.Fatal(err)
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
	}
}
