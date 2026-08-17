package fusefrontend

// Regression test for https://github.com/rfjakob/gocryptfs/issues/1024
//
// truncate(2) goes through node.Setattr, which opens its own file handle. That
// handle must take ContentLock like file.Setattr does: the lock doubles as the
// global write-operation counter that isConsecutiveWrite() uses to notice that
// somebody else changed the file. Without it, an already-open handle keeps
// believing its next write appends, skips writePadHole(), and leaves the last
// block short while the file grows past it - the block then fails to decrypt.

import (
	"bytes"
	"context"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
)

// issue1024Fs sets up a fusefrontend root over a temporary directory.
func issue1024Fs(t *testing.T) (*RootNode, string) {
	t.Helper()

	cipherdir := t.TempDir()
	key := make([]byte, cryptocore.KeyLen)
	cCore := cryptocore.New(key, cryptocore.BackendGoGCM, contentenc.DefaultIVBits, true)
	cEnc := contentenc.New(cCore, contentenc.DefaultBS)
	nt := nametransform.New(cCore.EMECipher, true, 255, true, nil, false)

	return NewRootNode(Args{Cipherdir: cipherdir}, cEnc, nt), filepath.Join(cipherdir, "backing")
}

// issue1024Open opens path as a File, like node.Open would.
func issue1024Open(t *testing.T, rn *RootNode, path string, flags int) *File {
	t.Helper()

	fd, err := syscall.Open(path, flags, 0600)
	if err != nil {
		t.Fatalf("open %q: %v", path, err)
	}
	f, _, errno := NewFile(fd, path, rn)
	if errno != 0 {
		t.Fatalf("NewFile: %v", errno)
	}
	t.Cleanup(func() {
		if !f.released {
			_ = f.Release(context.Background())
		}
	})

	return f
}

func TestTruncateThroughSecondHandleKeepsBlocksValid(t *testing.T) {
	rn, path := issue1024Fs(t)
	ctx := context.Background()

	// The handle the application keeps open, as in the issue's reproducer.
	f := issue1024Open(t, rn, path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL)

	block := make([]byte, contentenc.DefaultBS)
	for i := range block {
		block[i] = byte(i)
	}
	if _, errno := f.Write(ctx, block, 0); errno != 0 {
		t.Fatalf("write of a full block: %v", errno)
	}

	// truncate(2): node.Setattr opens a second handle for the truncate and
	// closes it again. The application's handle stays open and keeps its
	// file offset, which is why the next write lands past the new size.
	shrink := func(size uint64) {
		t.Helper()
		f2 := issue1024Open(t, rn, path, syscall.O_RDWR)
		if errno := f2.truncateLocked(size); errno != 0 {
			t.Fatalf("truncate(%d): %v", size, errno)
		}
		if errno := f2.Release(ctx); errno != 0 {
			t.Fatalf("release: %v", errno)
		}
	}

	shrink(8)

	payload := []byte("Test data!")
	if _, errno := f.Write(ctx, payload, int64(contentenc.DefaultBS)); errno != 0 {
		t.Fatalf("write past the new EOF: %v", errno)
	}

	// The write created a hole, so the first block had to be padded. If it was
	// not, it is now short and no longer decrypts.
	got, errno := f.doRead(nil, 0, contentenc.DefaultBS)
	if errno != 0 {
		t.Fatalf("reading the first block: %v", errno)
	}
	want := append(block[:8], bytes.Repeat([]byte{0}, contentenc.DefaultBS-8)...)
	if !bytes.Equal(got, want) {
		t.Errorf("first block: got %d bytes, want %d zero-padded bytes", len(got), len(want))
	}

	// The payload is still readable at its offset.
	got, errno = f.doRead(nil, uint64(contentenc.DefaultBS), uint64(len(payload)))
	if errno != 0 {
		t.Fatalf("reading the payload: %v", errno)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload: got %q, want %q", got, payload)
	}

	// And shrinking again works, which is where the issue reported EIO.
	shrink(7)
}
