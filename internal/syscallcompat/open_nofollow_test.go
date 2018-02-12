package syscallcompat

import (
	"os"
	"golang.org/x/sys/unix"
	"testing"
)

func TestOpenNofollow(t *testing.T) {
	err := os.MkdirAll(tmpDir+"/d1/d2/d3", 0700)
	if err != nil {
		t.Fatal(err)
	}
	// Create a file
	fd, err := OpenNofollow(tmpDir, "d1/d2/d3/f1", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	_, err = os.Stat(tmpDir + "/d1/d2/d3/f1")
	if err != nil {
		t.Fatal(err)
	}
	// Replace "d1" with a symlink - open should fail with ELOOP
	err = os.Rename(tmpDir+"/d1", tmpDir+"/d1.renamed")
	if err != nil {
		t.Fatal(err)
	}
	os.Symlink(tmpDir+"/d1.renamed", tmpDir+"/d1")
	fd, err = OpenNofollow(tmpDir, "d1/d2/d3/f1", unix.O_RDWR|unix.O_CREAT, 0600)
	if err == nil {
		t.Fatalf("should have failed")
	}
	if err != unix.ELOOP && err != unix.ENOTDIR {
		t.Errorf("expected ELOOP or ENOTDIR, got %v", err)
	}
	// Check to see that the base dir can be opened as well
	fd, err = OpenNofollow(tmpDir, "", unix.O_RDONLY, 0)
	if err != nil {
		t.Errorf("cannot open base dir: %v", err)
	} else {
		unix.Close(fd)
	}
}
