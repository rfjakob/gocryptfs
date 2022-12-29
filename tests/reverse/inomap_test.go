package reverse_test

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"
)

// findIno looks for the file having inode number `ino` in `dir`.
// Returns "" if not found.
func findIno(dir string, ino uint64) string {
	fd, err := os.Open(dir)
	if err != nil {
		return ""
	}
	dirents, err := fd.Readdirnames(0)
	if err != nil {
		return ""
	}
	fd.Close()
	for _, entry := range dirents {
		var st syscall.Stat_t
		err = syscall.Lstat(dir+"/"+entry, &st)
		if err != nil {
			continue
		}
		if ino == st.Ino {
			return entry
		}
	}
	return ""
}

// TestVirtualFileIno creates a directory tree like this:
//
//	TestVirtualFileIno  <---- parent
//	└── xxxxxxx[...]    <---- child
//
// Which looks like this encrypted:
//
//	OLUKdPMg6l87EiKVlufgwIkQL8MD6JdUgOR3a8nEZ-w                                <---- parent
//	├── gocryptfs.diriv                                                        <---- diriv
//	├── gocryptfs.longname.e31v1ax4h_F0l4jhlN8kCjaWWMq8rO9VVBZ15IYsV50         <---- child
//	└── gocryptfs.longname.e31v1ax4h_F0l4jhlN8kCjaWWMq8rO9VVBZ15IYsV50.name    <---- name
//
// It verifies that the inode numbers match what we expect.
func TestVirtualFileIno(t *testing.T) {
	if plaintextnames {
		t.Skip("plaintextnames mode does not have virtual files")
	}

	type inoTable struct {
		parent uint64
		diriv  uint64
		child  uint64
		name   uint64
	}
	var origInos inoTable
	var cipherInos inoTable

	parent := dirA + "/TestVirtualFileIno"
	name := string(bytes.Repeat([]byte("x"), 240))
	err := os.MkdirAll(parent+"/"+name, 0700)
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	err = syscall.Lstat(parent+"/"+name, &st)
	if err != nil {
		t.Fatal(err)
	}
	origInos.child = st.Ino
	// get inode number of plain parent
	err = syscall.Lstat(parent, &st)
	if err != nil {
		t.Fatal(err)
	}
	origInos.parent = st.Ino
	// find it in encrypted `dirB`
	fd, err := os.Open(dirB)
	if err != nil {
		t.Fatal(err)
	}
	dirents, err := fd.Readdirnames(0)
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	encryptedParent := findIno(dirB, origInos.parent)
	if encryptedParent == "" {
		t.Fatalf("could not find ino %d in %q", origInos.parent, dirB)
	}
	encryptedParent = dirB + "/" + encryptedParent
	err = syscall.Stat(encryptedParent, &st)
	if err != nil {
		t.Fatal(err)
	}
	cipherInos.parent = st.Ino
	fd, err = os.Open(encryptedParent)
	if err != nil {
		t.Fatal(err)
	}
	dirents, err = fd.Readdirnames(0)
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	for _, entry := range dirents {
		var st2 syscall.Stat_t
		err = syscall.Lstat(encryptedParent+"/"+entry, &st2)
		if err != nil {
			t.Errorf("stat %q: %v", entry, err)
			continue
		}
		if entry == "gocryptfs.diriv" {
			cipherInos.diriv = st2.Ino
		} else if strings.HasSuffix(entry, ".name") {
			cipherInos.name = st2.Ino
		} else {
			cipherInos.child = st2.Ino
		}
	}
	if origInos.parent != cipherInos.parent {
		t.Errorf("parent ino mismatch: %d != %d", origInos.parent, cipherInos.parent)
	}
	if origInos.parent == cipherInos.diriv {
		t.Errorf("diriv ino collision: %d == %d", origInos.parent, cipherInos.diriv)
	}
	// Lower 48 bits should come from the backing file
	const mask = 0xffffffffffff
	if !deterministic_names { // no diriv files with -deterministic-names
		if origInos.parent&mask != cipherInos.diriv&mask {
			t.Errorf("diriv ino mismatch: %#x vs %#x", origInos.parent, cipherInos.diriv)
		}
	}
	if origInos.child != cipherInos.child {
		t.Errorf("child ino mismatch: %d vs %d", origInos.child, cipherInos.child)
	}
	if origInos.child == cipherInos.name {
		t.Errorf("name ino collision: %d == %d", origInos.child, cipherInos.name)
	}
	if origInos.child&mask != cipherInos.name&mask {
		t.Errorf("name ino mismatch: %#x vs %#x", origInos.child, cipherInos.name)
	}
}
