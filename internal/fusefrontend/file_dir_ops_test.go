package fusefrontend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
)

func newFileLookupFS(t *testing.T, args Args, longNameMax uint8) (*RootNode, []byte) {
	t.Helper()

	args.Cipherdir = t.TempDir()
	var dirIV []byte
	if !args.PlaintextNames && !args.DeterministicNames {
		dirIV = make([]byte, nametransform.DirIVLen)
		dirIV[0] = 1
		err := os.WriteFile(filepath.Join(args.Cipherdir, nametransform.DirIVFilename), dirIV, 0400)
		if err != nil {
			t.Fatal(err)
		}
	}
	return newTestFSWithLongNameMax(args, longNameMax), dirIV
}

func createFileForLookup(t *testing.T, args Args, name string) (rn *RootNode, rawCName string) {
	t.Helper()

	rn, _ = newFileLookupFS(t, args, 0)
	_, fh, _, errno := rn.Create(context.Background(), name, syscall.O_WRONLY, 0600, &fuse.EntryOut{})
	if errno != 0 {
		t.Fatal(errno)
	}
	if errno = fh.(*File).Release(context.Background()); errno != 0 {
		t.Fatal(errno)
	}

	entries, err := os.ReadDir(rn.args.Cipherdir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		cName := entry.Name()
		if cName != nametransform.DirIVFilename &&
			nametransform.NameType(cName) != nametransform.LongNameFilename {
			rawCName = cName
			break
		}
	}
	if rawCName == "" {
		t.Fatal("could not find ciphertext content file")
	}
	return rn, rawCName
}

func openFileLookupDir(t *testing.T, rn *RootNode) *File {
	t.Helper()

	fh, _, errno := rn.OpendirHandle(context.Background(), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	file := fh.(*File)
	t.Cleanup(func() {
		file.Releasedir(context.Background(), 0)
	})
	return file
}

func readDirForFileLookup(t *testing.T, rn *RootNode, name string) *File {
	t.Helper()

	file := openFileLookupDir(t, rn)

	for {
		entry, errno := file.Readdirent(context.Background())
		if errno != 0 {
			t.Fatal(errno)
		}
		if entry == nil {
			t.Fatalf("did not find %q in directory", name)
		}
		if entry.Name == name {
			return file
		}
	}
}

func openDirForFileLookup(t *testing.T, args Args, name string) (rn *RootNode, file *File, rawCName string) {
	t.Helper()

	rn, rawCName = createFileForLookup(t, args, name)
	file = readDirForFileLookup(t, rn, name)
	return rn, file, rawCName
}

func TestFileLookupUsesRawCiphertextName(t *testing.T) {
	for _, tc := range []struct {
		testName string
		name     string
		args     Args
	}{
		{"short", "short", Args{LongNames: true}},
		{"long", strings.Repeat("l", 200), Args{LongNames: true}},
		{"plaintextnames", "plaintext", Args{PlaintextNames: true}},
		{"deterministic", "deterministic", Args{LongNames: true, DeterministicNames: true}},
	} {
		t.Run(tc.testName, func(t *testing.T) {
			rn, file, rawCName := openDirForFileLookup(t, tc.args, tc.name)

			if file.dirHandle.lastName != tc.name {
				t.Fatalf("lastName=%q, want %q", file.dirHandle.lastName, tc.name)
			}
			if file.dirHandle.lastCName != rawCName {
				t.Fatalf("lastCName=%q, want raw directory entry %q", file.dirHandle.lastCName, rawCName)
			}

			out := &fuse.EntryOut{}
			child, errno := file.Lookup(context.Background(), tc.name, out)
			if errno != 0 {
				t.Fatal(errno)
			}
			if child == nil || out.Mode&syscall.S_IFMT != syscall.S_IFREG {
				t.Fatalf("unexpected lookup result: child=%v mode=%#o", child, out.Mode)
			}

			nodeOut := &fuse.EntryOut{}
			nodeChild, errno := rn.Lookup(context.Background(), tc.name, nodeOut)
			if errno != 0 {
				t.Fatal(errno)
			}
			if child.StableAttr() != nodeChild.StableAttr() || out.Attr != nodeOut.Attr {
				t.Fatalf("File.Lookup and Node.Lookup differ:\nfile=%+v %#v\nnode=%+v %#v",
					child.StableAttr(), out.Attr, nodeChild.StableAttr(), nodeOut.Attr)
			}
		})
	}
}

func TestFileLookupSymlinkMatchesNodeLookup(t *testing.T) {
	const (
		name   = "link"
		target = "relative/target"
	)
	rn, _ := newFileLookupFS(t, Args{LongNames: true}, 0)
	_, errno := rn.Symlink(context.Background(), target, name, &fuse.EntryOut{})
	if errno != 0 {
		t.Fatal(errno)
	}
	file := readDirForFileLookup(t, rn, name)

	fileOut := &fuse.EntryOut{}
	fileChild, errno := file.Lookup(context.Background(), name, fileOut)
	if errno != 0 {
		t.Fatal(errno)
	}
	nodeOut := &fuse.EntryOut{}
	nodeChild, errno := rn.Lookup(context.Background(), name, nodeOut)
	if errno != 0 {
		t.Fatal(errno)
	}
	fileAttr := fileOut.Attr
	nodeAttr := nodeOut.Attr
	fileAttr.Atime, fileAttr.Atimensec = 0, 0
	nodeAttr.Atime, nodeAttr.Atimensec = 0, 0
	if fileChild.StableAttr() != nodeChild.StableAttr() || fileAttr != nodeAttr {
		t.Fatalf("File.Lookup and Node.Lookup differ:\nfile=%+v %#v\nnode=%+v %#v",
			fileChild.StableAttr(), fileAttr, nodeChild.StableAttr(), nodeAttr)
	}
	if fileOut.Size != uint64(len(target)) {
		t.Fatalf("symlink size=%d, want %d", fileOut.Size, len(target))
	}
}

func TestFileLookupFastPath(t *testing.T) {
	name := "file"
	rn, file, _ := openDirForFileLookup(t, Args{LongNames: true}, name)

	// Make Node.Lookup fail while leaving the open directory handle usable.
	// File.Lookup can now succeed only through the retained-name fast path.
	rn.dirCache.Clear()
	if err := os.Remove(filepath.Join(rn.args.Cipherdir, nametransform.DirIVFilename)); err != nil {
		t.Fatal(err)
	}

	child, errno := file.Lookup(context.Background(), name, &fuse.EntryOut{})
	if errno != 0 {
		t.Fatal(errno)
	}
	if child == nil {
		t.Fatal("fast-path lookup returned a nil child")
	}
}

func TestFileLookupRejectsNoncanonicalLongName(t *testing.T) {
	name := "short"
	rn, rawCName := createFileForLookup(t, Args{LongNames: true}, name)

	// Store a short ciphertext through the long-name representation. Both
	// entries decrypt to name, but only rawCName is canonical.
	hashName := rn.nameTransform.HashLongName(rawCName)
	if err := os.WriteFile(filepath.Join(rn.args.Cipherdir, hashName), nil, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rn.args.Cipherdir, hashName+nametransform.LongNameSuffix),
		[]byte(rawCName), 0400); err != nil {
		t.Fatal(err)
	}

	file := openFileLookupDir(t, rn)
	for {
		entry, errno := file.Readdirent(context.Background())
		if errno != 0 {
			t.Fatal(errno)
		}
		if entry == nil {
			t.Fatalf("did not find noncanonical entry for %q", name)
		}
		if entry.Name == name && file.dirHandle.lastCName == "" {
			break
		}
	}

	out := &fuse.EntryOut{}
	_, errno := file.Lookup(context.Background(), name, out)
	if errno != 0 {
		t.Fatal(errno)
	}
	if out.Mode&0777 != 0600 {
		t.Fatalf("lookup used noncanonical mode %#o, want 0600", out.Mode&0777)
	}
}

func TestFileLookupRejectsUnhashedLongName(t *testing.T) {
	const longNameMax = 100
	name := strings.Repeat("n", 80)
	rn, dirIV := newFileLookupFS(t, Args{LongNames: true}, longNameMax)
	rawCName, err := rn.nameTransform.EncryptName(name, dirIV)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawCName) <= longNameMax {
		t.Fatalf("ciphertext name has length %d, want > %d", len(rawCName), longNameMax)
	}
	if err := os.WriteFile(filepath.Join(rn.args.Cipherdir, rawCName), nil, 0600); err != nil {
		t.Fatal(err)
	}
	rn.MitigatedCorruptions = make(chan string, 1)

	file := readDirForFileLookup(t, rn, name)
	if file.dirHandle.lastCName != "" {
		t.Fatalf("retained noncanonical unhashed name %q", file.dirHandle.lastCName)
	}
	select {
	case got := <-rn.MitigatedCorruptions:
		if got != rawCName {
			t.Fatalf("reported corruption %q, want %q", got, rawCName)
		}
	default:
		t.Fatal("noncanonical unhashed name was not reported as corruption")
	}
	child, errno := file.Lookup(context.Background(), name, &fuse.EntryOut{})
	if errno != syscall.ENOENT || child != nil {
		t.Fatalf("lookup result: child=%v errno=%v, want nil, ENOENT", child, errno)
	}
}

func TestFileLookupRejectsMismatchedLongNameSidecar(t *testing.T) {
	name := strings.Repeat("l", 200)
	rn, rawCName := createFileForLookup(t, Args{LongNames: true}, name)

	otherName := "other"
	dirIV, err := os.ReadFile(filepath.Join(rn.args.Cipherdir, nametransform.DirIVFilename))
	if err != nil {
		t.Fatal(err)
	}
	cName, err := rn.nameTransform.EncryptName(otherName, dirIV)
	if err != nil {
		t.Fatal(err)
	}
	sidecar := filepath.Join(rn.args.Cipherdir, rawCName+nametransform.LongNameSuffix)
	if err := os.Chmod(sidecar, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecar, []byte(cName), 0600); err != nil {
		t.Fatal(err)
	}

	file := readDirForFileLookup(t, rn, otherName)
	if file.dirHandle.lastCName != "" {
		t.Fatalf("retained noncanonical ciphertext name %q", file.dirHandle.lastCName)
	}
	child, errno := file.Lookup(context.Background(), otherName, &fuse.EntryOut{})
	if errno != syscall.ENOENT || child != nil {
		t.Fatalf("lookup result: child=%v errno=%v, want nil, ENOENT", child, errno)
	}
}

func TestFileLookupFallsBackAfterSeek(t *testing.T) {
	name := "file"
	_, file, _ := openDirForFileLookup(t, Args{LongNames: true}, name)

	if errno := file.Seekdir(context.Background(), 0); errno != 0 {
		t.Fatal(errno)
	}
	if file.dirHandle.lastName != "" || file.dirHandle.lastCName != "" {
		t.Fatal("Seekdir did not clear the retained name mapping")
	}

	child, errno := file.Lookup(context.Background(), name, &fuse.EntryOut{})
	if errno != 0 {
		t.Fatal(errno)
	}
	if child == nil {
		t.Fatal("fallback lookup returned a nil child")
	}
}

func TestFileLookupResetsIdleMarker(t *testing.T) {
	name := "file"
	rn, file, _ := openDirForFileLookup(t, Args{LongNames: true}, name)

	rn.IsIdle.Store(true)
	_, errno := file.Lookup(context.Background(), name, &fuse.EntryOut{})
	if errno != 0 {
		t.Fatal(errno)
	}
	if rn.IsIdle.Load() {
		t.Fatal("File.Lookup did not reset the idle marker")
	}
}

func TestFileLookupPreservesLookupBehavior(t *testing.T) {
	name := "file"
	owner := fuse.Owner{Uid: 1234, Gid: 5678}
	rn, file, _ := openDirForFileLookup(t, Args{
		ForceOwner:    &owner,
		LongNames:     true,
		SharedStorage: true,
	}, name)

	out := &fuse.EntryOut{}
	child, errno := file.Lookup(context.Background(), name, out)
	if errno != 0 {
		t.Fatal(errno)
	}
	if out.Owner != owner {
		t.Fatalf("owner=%v, want %v", out.Owner, owner)
	}

	rn.AddChild(name, child, false)
	out = &fuse.EntryOut{}
	child2, errno := file.Lookup(context.Background(), name, out)
	if errno != 0 {
		t.Fatal(errno)
	}
	if child2 != child {
		t.Fatal("-sharedstorage lookup did not reuse the existing child")
	}
	if out.Owner != owner {
		t.Fatalf("owner=%v, want %v", out.Owner, owner)
	}
}
