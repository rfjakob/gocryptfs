package fusefrontend

import (
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func TestOpenBackingDir(t *testing.T) {
	cipherdir := test_helpers.InitFS(t)
	args := Args{
		Cipherdir: cipherdir,
	}
	fs := newTestFS(args)

	code := fs.Mkdir("dir1", 0700, nil)
	if !code.Ok() {
		t.Fatal(code)
	}
	code = fs.Mkdir("dir1/dir2", 0700, nil)
	if !code.Ok() {
		t.Fatal(code)
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
	if cName == "" {
		t.Fatal("cName should not be empty")
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
	if cName == "" {
		t.Fatal("cName should not be empty")
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	n255 := strings.Repeat("n", 255)
	path := "dir1/" + n255
	fs.Mkdir(path, 0700, nil)
	dirfd, cName, err = fs.openBackingDir(path)
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
		t.Error(err)
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

	code := fs.Mkdir("dir1", 0700, nil)
	if !code.Ok() {
		t.Fatal(code)
	}
	code = fs.Mkdir("dir1/dir2", 0700, nil)
	if !code.Ok() {
		t.Fatal(code)
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
