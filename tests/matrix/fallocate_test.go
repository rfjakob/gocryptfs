package matrix

import (
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

const (
	// From man statfs
	TMPFS_MAGIC      = 0x01021994
	EXT4_SUPER_MAGIC = 0xef53
)

// isWellKnownFS decides if the backing filesystem is well-known.
// The expected allocated sizes are only valid on tmpfs and ext4. btrfs
// gives different results, but that's not an error.
func isWellKnownFS(fn string) bool {
	var fs syscall.Statfs_t
	err := syscall.Statfs(fn, &fs)
	if err != nil {
		panic(err)
	}
	if fs.Type == EXT4_SUPER_MAGIC || fs.Type == TMPFS_MAGIC {
		return true
	}
	return false
}

const FALLOC_DEFAULT = 0x00
const FALLOC_FL_KEEP_SIZE = 0x01

func TestFallocate(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skipf("OSX does not support fallocate")
	}
	fn := test_helpers.DefaultPlainDir + "/fallocate"
	file, err := os.Create(fn)
	if err != nil {
		t.FailNow()
	}
	defer file.Close()
	wellKnown := isWellKnownFS(test_helpers.DefaultCipherDir)
	fd := int(file.Fd())
	nBytes := test_helpers.Du(t, fd)
	if nBytes != 0 {
		t.Fatalf("Empty file has %d bytes", nBytes)
	}
	// Allocate 30 bytes, keep size
	// gocryptfs ||        (0 blocks)
	//      ext4 |  d   |  (1 block)
	//              ^ d = data block
	err = syscallcompat.Fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 30)
	if err != nil {
		t.Error(err)
	}
	var want int64
	nBytes = test_helpers.Du(t, fd)
	want = 4096
	if nBytes != want {
		t.Errorf("Expected %d allocated bytes, have %d", want, nBytes)
	}
	test_helpers.VerifySize(t, fn, 0)
	// Three ciphertext blocks. The middle one should be a file hole.
	// gocryptfs |  h   |   h  | d|   (1 block)
	//      ext4 |  d  |  h  |  d  |  (2 blocks)
	//                    ^ h = file hole
	// (Note that gocryptfs blocks are slightly bigger than the ext4 blocks,
	// but the last one is partial)
	err = file.Truncate(9000)
	if err != nil {
		t.Fatal(err)
	}
	nBytes = test_helpers.Du(t, fd)
	want = 2 * 4096
	if wellKnown && nBytes != want {
		t.Errorf("Expected %d allocated bytes, have %d", want, nBytes)
	}
	if md5 := test_helpers.Md5fn(fn); md5 != "5420afa22f6423a9f59e669540656bb4" {
		t.Errorf("Wrong md5 %s", md5)
	}
	// Allocate the whole file space
	// gocryptfs |  h   |   h  | d|   (1 block)
	//      ext4 |  d  |  d  |  d  |  (3 blocks
	err = syscallcompat.Fallocate(fd, FALLOC_DEFAULT, 0, 9000)
	if err != nil {
		t.Fatal(err)
	}
	nBytes = test_helpers.Du(t, fd)
	want = 3 * 4096
	if nBytes != want {
		t.Errorf("Expected %d allocated bytes, have %d", want, nBytes)
	}
	// Neither apparent size nor content should have changed
	test_helpers.VerifySize(t, fn, 9000)
	if md5 := test_helpers.Md5fn(fn); md5 != "5420afa22f6423a9f59e669540656bb4" {
		t.Errorf("Wrong md5 %s", md5)
	}

	// Partial block on the end. The first ext4 block is dirtied by the header.
	// gocryptfs |  h   |   h  | d|   (1 block)
	//      ext4 |  d  |  h  |  d  |  (2 blocks)
	file.Truncate(0)
	file.Truncate(9000)
	nBytes = test_helpers.Du(t, fd)
	want = 2 * 4096
	if wellKnown && nBytes != want {
		t.Errorf("Expected %d allocated bytes, have %d", want, nBytes)
	}
	// Allocate 10 bytes in the second block
	// gocryptfs |  h   |   h  | d|   (1 block)
	//      ext4 |  d  |  d  |  d  |  (3 blocks)
	syscallcompat.Fallocate(fd, FALLOC_DEFAULT, 5000, 10)
	nBytes = test_helpers.Du(t, fd)
	want = 3 * 4096
	if wellKnown && nBytes != want {
		t.Errorf("Expected %d allocated bytes, have %d", want, nBytes)
	}
	// Neither apparent size nor content should have changed
	test_helpers.VerifySize(t, fn, 9000)
	if md5 := test_helpers.Md5fn(fn); md5 != "5420afa22f6423a9f59e669540656bb4" {
		t.Errorf("Wrong md5 %s", md5)
	}
	// Grow the file to 4 blocks
	// gocryptfs |  h   |  h   |  d   |d|  (2 blocks)
	//      ext4 |  d  |  d  |  d  |  d  | (4 blocks)
	syscallcompat.Fallocate(fd, FALLOC_DEFAULT, 15000, 10)
	nBytes = test_helpers.Du(t, fd)
	want = 4 * 4096
	if wellKnown && nBytes != want {
		t.Errorf("Expected %d allocated bytes, have %d", want, nBytes)
	}
	test_helpers.VerifySize(t, fn, 15010)
	if md5 := test_helpers.Md5fn(fn); md5 != "c4c44c7a41ab7798a79d093eb44f99fc" {
		t.Errorf("Wrong md5 %s", md5)
	}
	// Shrinking a file using fallocate should have no effect
	for _, off := range []int64{0, 10, 2000, 5000} {
		for _, sz := range []int64{0, 1, 42, 6000} {
			syscallcompat.Fallocate(fd, FALLOC_DEFAULT, off, sz)
			test_helpers.VerifySize(t, fn, 15010)
			if md5 := test_helpers.Md5fn(fn); md5 != "c4c44c7a41ab7798a79d093eb44f99fc" {
				t.Errorf("Wrong md5 %s", md5)
			}
		}
	}
	// We used to allocate 18 bytes too much:
	// https://github.com/rfjakob/gocryptfs/issues/311
	//
	// 8110 bytes of plaintext should get us exactly 8192 bytes of ciphertext.
	err = file.Truncate(0)
	if err != nil {
		t.Fatal(err)
	}
	var plain int64 = 8110
	if testcase.isSet("-xchacha") {
		// xchacha has 24 byte ivs instead of 16. 8kiB are two blocks, so
		// 2x8=16 bytes more.
		plain = plain - 16
	}
	err = syscallcompat.Fallocate(fd, FALLOC_DEFAULT, 0, plain)
	if err != nil {
		t.Fatal(err)
	}
	nBytes = test_helpers.Du(t, fd)
	want = 8192
	if nBytes != want {
		t.Errorf("Expected %d allocated bytes, have %d", want, nBytes)
	}
	// Cleanup
	syscall.Unlink(fn)
	if !wellKnown {
		// Even though most tests have been executed still, inform the user
		// that some were disabled
		t.Skipf("backing fs is not ext4 or tmpfs, skipped some disk-usage checks\n")
	}
}
