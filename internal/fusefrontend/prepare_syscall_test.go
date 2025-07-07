package fusefrontend

import (
	"context"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestPrepareAtSyscall(t *testing.T) {
	cipherdir := test_helpers.InitFS(t)
	t.Logf("cipherdir = %q", cipherdir)
	args := Args{
		Cipherdir: cipherdir,
	}
	rn := newTestFS(args)
	out := &fuse.EntryOut{}

	child, errno := rn.Mkdir(context.TODO(), "dir1", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}
	rn.AddChild("dir1", child, false)
	dir1 := toNode(child.Operations())
	_, errno = dir1.Mkdir(context.TODO(), "dir2", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}

	dirfd, cName, errno := rn.prepareAtSyscallMyself()
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName != "." {
		t.Fatal("cName should be .")
	}
	syscall.Close(dirfd)

	// Again, but populate the cache for "" by looking up a non-existing file
	rn.Lookup(context.TODO(), "xyz1234", &fuse.EntryOut{})
	dirfd, cName, errno = rn.prepareAtSyscallMyself()
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName != "." {
		t.Fatal("cName should be .")
	}

	err := syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	err = syscallcompat.Faccessat(dirfd, ".", unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, errno = rn.prepareAtSyscall("dir1")
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName == "" {
		t.Fatal("cName should not be empty")
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, errno = dir1.prepareAtSyscall("dir2")
	if errno != 0 {
		t.Fatal(errno)
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
	dir1.Mkdir(context.TODO(), n255, 0700, out)
	dirfd, cName, errno = dir1.prepareAtSyscall(n255)
	if errno != 0 {
		t.Fatal(errno)
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

func TestPrepareAtSyscallPlaintextnames(t *testing.T) {
	cipherdir := test_helpers.InitFS(t, "-plaintextnames")
	args := Args{
		Cipherdir:      cipherdir,
		PlaintextNames: true,
	}
	rn := newTestFS(args)
	out := &fuse.EntryOut{}

	child, errno := rn.Mkdir(context.TODO(), "dir1", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}
	rn.AddChild("dir1", child, false)
	dir1 := toNode(child.Operations())
	_, errno = dir1.Mkdir(context.TODO(), "dir2", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}

	dirfd, cName, errno := rn.prepareAtSyscallMyself()
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName != "." {
		t.Fatal("cName should be .")
	}
	err := syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	err = syscallcompat.Faccessat(dirfd, ".", unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, errno = rn.prepareAtSyscall("dir1")
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName != "dir1" {
		t.Fatalf("wrong cName: %q", cName)
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, errno = dir1.prepareAtSyscall("dir2")
	if errno != 0 {
		t.Fatal(errno)
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
