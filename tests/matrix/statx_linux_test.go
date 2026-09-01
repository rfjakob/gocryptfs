package matrix

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

const testStatxMask = unix.STATX_BASIC_STATS | unix.STATX_BTIME

func statxAt(t *testing.T, dirfd int, path string, flags int) unix.Statx_t {
	t.Helper()
	var st unix.Statx_t
	if err := unix.Statx(dirfd, path, flags, testStatxMask, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func encryptedPath(t *testing.T, plainPath string) string {
	t.Helper()
	resp := test_helpers.QueryCtlSock(t, ctlsockPath, ctlsock.RequestStruct{
		EncryptPath: plainPath,
	})
	if resp.Result == "" {
		t.Fatal(resp)
	}
	return filepath.Join(test_helpers.DefaultCipherDir, resp.Result)
}

func requireFuseStatx(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(data)), ".", 3)
	if len(parts) < 2 {
		t.Skipf("cannot parse kernel release %q", data)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Skipf("cannot parse kernel release %q: %v", data, err)
	}
	minorString := parts[1]
	if i := strings.IndexFunc(minorString, func(r rune) bool {
		return r < '0' || r > '9'
	}); i >= 0 {
		minorString = minorString[:i]
	}
	minor, err := strconv.Atoi(minorString)
	if err != nil {
		t.Skipf("cannot parse kernel release %q: %v", data, err)
	}
	if major < 6 || major == 6 && minor < 6 {
		t.Skip("FUSE_STATX requires Linux 6.6 or newer")
	}
}

func checkBtime(t *testing.T, plainPath string, cipherPath string, flags int) unix.Statx_t {
	t.Helper()
	cipherSt := statxAt(t, unix.AT_FDCWD, cipherPath, flags)
	if cipherSt.Mask&unix.STATX_BTIME == 0 {
		t.Skip("backing filesystem does not report STATX_BTIME")
	}
	plainSt := statxAt(t, unix.AT_FDCWD, plainPath, flags)
	if plainSt.Mask&unix.STATX_BTIME == 0 {
		t.Fatalf("mounted filesystem did not report STATX_BTIME: mask=%#x", plainSt.Mask)
	}
	if plainSt.Btime.Sec != cipherSt.Btime.Sec || plainSt.Btime.Nsec != cipherSt.Btime.Nsec {
		t.Errorf("birth time mismatch: plain=%d.%09d cipher=%d.%09d",
			plainSt.Btime.Sec, plainSt.Btime.Nsec,
			cipherSt.Btime.Sec, cipherSt.Btime.Nsec)
	}
	return plainSt
}

func TestStatxBtime(t *testing.T) {
	requireFuseStatx(t)

	t.Run("root", func(t *testing.T) {
		checkBtime(t, test_helpers.DefaultPlainDir, test_helpers.DefaultCipherDir, unix.AT_SYMLINK_NOFOLLOW)
	})

	t.Run("regular", func(t *testing.T) {
		const content = "statx birth time"
		relPath := strings.ReplaceAll(t.Name(), "/", "_")
		plainPath := filepath.Join(test_helpers.DefaultPlainDir, relPath)
		if err := os.WriteFile(plainPath, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		cipherPath := encryptedPath(t, relPath)

		before := checkBtime(t, plainPath, cipherPath, unix.AT_SYMLINK_NOFOLLOW)
		if before.Size != uint64(len(content)) {
			t.Errorf("wrong plaintext size: have=%d want=%d", before.Size, len(content))
		}

		// Check user-visible AT_EMPTY_PATH behavior. Current Linux kernels do
		// not send the file handle in FUSE_STATX, so this still reaches
		// Node.Statx rather than File.Statx.
		f, err := os.Open(plainPath)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		fdSt := statxAt(t, int(f.Fd()), "", unix.AT_EMPTY_PATH)
		if fdSt.Mask&unix.STATX_BTIME == 0 {
			t.Fatalf("statx on open file did not report STATX_BTIME: mask=%#x", fdSt.Mask)
		}
		if fdSt.Btime.Sec != before.Btime.Sec || fdSt.Btime.Nsec != before.Btime.Nsec {
			t.Errorf("statx on open file returned different birth time: path=%d.%09d fd=%d.%09d",
				before.Btime.Sec, before.Btime.Nsec, fdSt.Btime.Sec, fdSt.Btime.Nsec)
		}

		now := time.Now().Add(-time.Hour)
		if err := os.Chtimes(plainPath, now, now); err != nil {
			t.Fatal(err)
		}
		after := checkBtime(t, plainPath, cipherPath, unix.AT_SYMLINK_NOFOLLOW)
		if after.Btime.Sec != before.Btime.Sec || after.Btime.Nsec != before.Btime.Nsec {
			t.Errorf("birth time changed with mtime: before=%d.%09d after=%d.%09d",
				before.Btime.Sec, before.Btime.Nsec, after.Btime.Sec, after.Btime.Nsec)
		}
	})

	t.Run("directory", func(t *testing.T) {
		relPath := strings.ReplaceAll(t.Name(), "/", "_")
		plainPath := filepath.Join(test_helpers.DefaultPlainDir, relPath)
		if err := os.Mkdir(plainPath, 0700); err != nil {
			t.Fatal(err)
		}
		checkBtime(t, plainPath, encryptedPath(t, relPath), unix.AT_SYMLINK_NOFOLLOW)
	})

	t.Run("symlink", func(t *testing.T) {
		const target = "/target/does/not/exist"
		relPath := strings.ReplaceAll(t.Name(), "/", "_")
		plainPath := filepath.Join(test_helpers.DefaultPlainDir, relPath)
		if err := os.Symlink(target, plainPath); err != nil {
			t.Fatal(err)
		}
		st := checkBtime(t, plainPath, encryptedPath(t, relPath), unix.AT_SYMLINK_NOFOLLOW)
		if st.Size != uint64(len(target)) {
			t.Errorf("wrong symlink size: have=%d want=%d", st.Size, len(target))
		}
	})
}
