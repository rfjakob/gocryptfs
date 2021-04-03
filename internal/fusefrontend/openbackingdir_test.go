package fusefrontend

import (
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func TestOpenBackingDir(t *testing.T) {
	cipherdir := test_helpers.InitFS(t)
	t.Logf("cipherdir = %q", cipherdir)
	args := Args{
		Cipherdir: cipherdir,
	}
	rn := newTestFS(args)
	out := &fuse.EntryOut{}

	child, errno := rn.Mkdir(nil, "dir1", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}
	rn.AddChild("dir1", child, false)
	dir1 := toNode(child.Operations())
	_, errno = dir1.Mkdir(nil, "dir2", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}

	dirfd, cName, err := rn.openBackingDir("")
	if err != nil {
		t.Fatal(err)
	}
	if cName != "." {
		t.Fatal("cName should be .")
	}
	syscall.Close(dirfd)

	// Again, but populate the cache for "" by looking up a non-existing file
	rn.Lookup(nil, "xyz1234", &fuse.EntryOut{})
	dirfd, cName, err = rn.openBackingDir("")
	if err != nil {
		t.Fatal(err)
	}
	if cName != "." {
		t.Fatal("cName should be .")
	}

	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	err = syscallcompat.Faccessat(dirfd, ".", unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, err = rn.openBackingDir("dir1")
	if err != nil {
		t.Fatal(err)
	}
	if cName == "" {
		t.Fatal("cName should not be empty")
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, err = rn.openBackingDir("dir1/dir2")
	if err != nil {
		t.Fatal(err)
	}
	if cName == "" {
		t.Fatal("cName should not be empty")
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Errorf("Faccessat(%d, %q): %v", dirfd, cName, err)
	}
	syscall.Close(dirfd)

	n255 := strings.Repeat("n", 255)
	dir1.Mkdir(nil, n255, 0700, out)
	dirfd, cName, err = rn.openBackingDir("dir1/" + n255)
	if err != nil {
		t.Fatal(err)
	}
	if cName == "" {
		t.Fatal("cName should not be empty")
	}
	if len(cName) >= 255 {
		t.Fatalf("cName is too long: %q", cName)
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Errorf("Faccessat(%d, %q): %v", dirfd, cName, err)
	}
	syscall.Close(dirfd)
}

func TestOpenBackingDirPlaintextNames(t *testing.T) {
	cipherdir := test_helpers.InitFS(t, "-plaintextnames")
	args := Args{
		Cipherdir:      cipherdir,
		PlaintextNames: true,
	}
	fs := newTestFS(args)
	out := &fuse.EntryOut{}

	_, errno := fs.Mkdir(nil, "dir1", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}
	_, errno = fs.Mkdir(nil, "dir1/dir2", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}

	dirfd, cName, err := fs.openBackingDir("")
	if err != nil {
		t.Fatal(err)
	}
	if cName != "." {
		t.Fatal("cName should be .")
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	err = syscallcompat.Faccessat(dirfd, ".", unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, err = fs.openBackingDir("dir1")
	if err != nil {
		t.Fatal(err)
	}
	if cName != "dir1" {
		t.Fatalf("wrong cName: %q", cName)
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, err = fs.openBackingDir("dir1/dir2")
	if err != nil {
		t.Fatal(err)
	}
	if cName != "dir2" {
		t.Fatalf("wrong cName: %q", cName)
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)
}
