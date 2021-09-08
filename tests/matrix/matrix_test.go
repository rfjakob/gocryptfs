// Tests run for (almost all) combinations of openssl, aessiv, plaintextnames.
package matrix

// File reading, writing, modification, truncate, ...
//
// Runs all tests N times, for the combinations of different flags specified
// in the `matrix` variable.

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// Several tests need to be aware if plaintextnames is active or not, so make this
// a global variable
var testcase testcaseMatrix

type testcaseMatrix struct {
	plaintextnames bool
	openssl        string
	aessiv         bool
	raw64          bool
	extraArgs      []string
}

// isSet finds out if `extraArg` is set in `tc.extraArgs`
func (tc *testcaseMatrix) isSet(extraArg string) bool {
	for _, v := range tc.extraArgs {
		if v == extraArg {
			return true
		}
	}
	return false
}

var matrix = []testcaseMatrix{
	// Normal
	{false, "auto", false, false, nil},
	{false, "true", false, false, nil},
	{false, "false", false, false, nil},
	// Plaintextnames
	{true, "true", false, false, nil},
	{true, "false", false, false, nil},
	// AES-SIV (does not use openssl, no need to test permutations)
	{false, "auto", true, false, nil},
	{true, "auto", true, false, nil},
	// Raw64
	{false, "auto", false, true, nil},
	// -serialize_reads
	{false, "auto", false, false, []string{"-serialize_reads"}},
	{false, "auto", false, false, []string{"-sharedstorage"}},
	{false, "auto", false, false, []string{"-deterministic-names"}},
	// Test xchacha with and without openssl
	{false, "true", false, true, []string{"-xchacha"}},
	{false, "false", false, true, []string{"-xchacha"}},
}

// This is the entry point for the tests
func TestMain(m *testing.M) {
	// Make "testing.Verbose()" return the correct value
	flag.Parse()
	var i int
	for i, testcase = range matrix {
		if testcase.openssl == "true" && stupidgcm.BuiltWithoutOpenssl {
			continue
		}
		if testing.Verbose() {
			fmt.Printf("matrix: testcase = %#v\n", testcase)
		}
		createDirIV := true
		if testcase.plaintextnames {
			createDirIV = false
		} else if testcase.isSet("-deterministic-names") {
			createDirIV = false
		}
		test_helpers.ResetTmpDir(createDirIV)
		opts := []string{"-zerokey"}
		//opts = append(opts, "-fusedebug")
		opts = append(opts, fmt.Sprintf("-openssl=%v", testcase.openssl))
		opts = append(opts, fmt.Sprintf("-plaintextnames=%v", testcase.plaintextnames))
		opts = append(opts, fmt.Sprintf("-aessiv=%v", testcase.aessiv))
		opts = append(opts, fmt.Sprintf("-raw64=%v", testcase.raw64))
		opts = append(opts, testcase.extraArgs...)
		test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, opts...)
		before := test_helpers.ListFds(0, test_helpers.TmpDir)
		t0 := time.Now()
		r := m.Run()
		if testing.Verbose() {
			fmt.Printf("matrix: run took %v\n", time.Since(t0))
		}
		// Catch fd leaks in the tests. NOTE: this does NOT catch leaks in
		// the gocryptfs FUSE process, but only in the tests that access it!
		// All fds that point outside TmpDir are not interesting (the Go test
		// infrastucture creates temporary log files we don't care about).
		after := test_helpers.ListFds(0, test_helpers.TmpDir)
		if len(before) != len(after) {
			fmt.Printf("fd leak in test process? before, after:\n%v\n%v\n", before, after)
			os.Exit(1)
		}
		test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
		if r != 0 {
			fmt.Printf("TestMain: matrix[%d] = %#v failed\n", i, testcase)
			os.Exit(r)
		}
	}
	os.Exit(0)
}

// Write `n` random bytes to filename `fn`, read again, compare hash
func testWriteN(t *testing.T, fn string, n int) string {
	file, err := os.Create(test_helpers.DefaultPlainDir + "/" + fn)
	if err != nil {
		t.Fatal(err)
	}

	d := make([]byte, n)
	for i := range d {
		// Fill with pattern
		d[i] = byte(rand.Int())
	}
	_, err = file.Write(d)
	if err != nil {
		t.Fatal(err)
	}
	err = file.Close()
	if err != nil {
		t.Fatal(err)
	}

	test_helpers.VerifySize(t, test_helpers.DefaultPlainDir+"/"+fn, n)

	hashWant := test_helpers.Md5hex(d)

	hashActual := test_helpers.Md5fn(test_helpers.DefaultPlainDir + "/" + fn)

	if hashActual != hashWant {
		t.Errorf("Wrong content, hashWant=%s hashActual=%s", hashWant, hashActual)
	}

	return hashActual
}

func TestWrite10(t *testing.T) {
	testWriteN(t, "10", 10)
}

func TestWrite100(t *testing.T) {
	testWriteN(t, "100", 100)
}

func TestWrite1M(t *testing.T) {
	testWriteN(t, "1M", 1024*1024)
}

func TestWrite100x100(t *testing.T) {
	hashWant := testWriteN(t, "100x100", 100)
	// Read and check 100 times to catch race conditions
	var i int
	for i = 0; i < 100; i++ {
		hashActual := test_helpers.Md5fn(test_helpers.DefaultPlainDir + "/100x100")
		if hashActual != hashWant {
			fmt.Printf("Read corruption in loop #%d: have=%s want=%s\n", i, hashActual, hashWant)
			t.FailNow()
		} else {
			//fmt.Print(".")
		}
	}
}

func TestWrite10Tight(t *testing.T) {
	path := test_helpers.DefaultPlainDir + "/TestWrite10Tight"
	content := make([]byte, 10)
	buf := make([]byte, 100)
	for i := 0; i < 100; i++ {
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.Write(content)
		if err != nil {
			t.Fatal(err)
		}
		err = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		file, err = os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		n, err := file.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n != 10 {
			t.Fatalf("want 10 bytes, got %d", n)
		}
		err = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = os.Remove(path)
		if err != nil {
			t.Fatal()
		}
	}
}

// Hint for calculating reference md5sums:
// dd if=/dev/zero count=1 bs=XYZ | md5sum
func TestTruncate(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/truncate"
	file, err := os.Create(fn)
	if err != nil {
		t.FailNow()
	}
	defer file.Close()
	// Grow to two blocks
	file.Truncate(7000)
	test_helpers.VerifySize(t, fn, 7000)
	if md5 := test_helpers.Md5fn(fn); md5 != "95d4ec7038e3e4fdbd5f15c34c3f0b34" {
		t.Errorf("Wrong md5 %s", md5)
	}
	// Shrink - needs RMW
	file.Truncate(6999)
	test_helpers.VerifySize(t, fn, 6999)
	if md5 := test_helpers.Md5fn(fn); md5 != "35fd15873ec6c35380064a41b9b9683b" {
		t.Errorf("Wrong md5 %s", md5)
	}
	// Shrink to one partial block
	file.Truncate(465)
	test_helpers.VerifySize(t, fn, 465)
	if md5 := test_helpers.Md5fn(fn); md5 != "a1534d6e98a6b21386456a8f66c55260" {
		t.Errorf("Wrong md5 %s", md5)
	}
	// Grow to exactly one block
	file.Truncate(4096)
	test_helpers.VerifySize(t, fn, 4096)
	if md5 := test_helpers.Md5fn(fn); md5 != "620f0b67a91f7f74151bc5be745b7110" {
		t.Errorf("Wrong md5 %s", md5)
	}
	// Truncate to zero
	file.Truncate(0)
	test_helpers.VerifySize(t, fn, 0)
	// Grow to 10MB (creates file holes)
	var sz int
	sz = 10 * 1024 * 1024
	file.Truncate(int64(sz))
	test_helpers.VerifySize(t, fn, sz)
	if md5 := test_helpers.Md5fn(fn); md5 != "f1c9645dbc14efddc7d8a322685f26eb" {
		t.Errorf("Wrong md5 %s", md5)
	}
	// Grow to 10MB + 100B (partial block on the end)
	sz = 10*1024*1024 + 100
	file.Truncate(int64(sz))
	test_helpers.VerifySize(t, fn, sz)
	if md5 := test_helpers.Md5fn(fn); md5 != "c23ea79b857b91a7ff07c6ecf185f1ca" {
		t.Errorf("Wrong md5 %s", md5)
	}
	// Grow to 20MB (creates file holes, partial block on the front)
	sz = 20 * 1024 * 1024
	file.Truncate(int64(sz))
	test_helpers.VerifySize(t, fn, sz)
	if md5 := test_helpers.Md5fn(fn); md5 != "8f4e33f3dc3e414ff94e5fb6905cba8c" {
		t.Errorf("Wrong md5 %s", md5)
	}
}

func TestAppend(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/append"
	file, err := os.Create(fn)
	if err != nil {
		t.FailNow()
	}
	defer file.Close()
	data := []byte("testdata123456789") // length 17
	var buf bytes.Buffer
	var hashWant string
	for i := 0; i <= 500; i++ {
		file.Write(data)
		buf.Write(data)
		hashWant = test_helpers.Md5hex(buf.Bytes())
		hashActual := test_helpers.Md5fn(fn)
		if hashWant != hashActual {
			t.FailNow()
		}
	}

	// Overwrite with the same data
	// Hash must stay the same
	file.Seek(0, 0)
	for i := 0; i <= 500; i++ {
		file.Write(data)
		hashActual := test_helpers.Md5fn(fn)
		if hashWant != hashActual {
			t.FailNow()
		}
	}
}

// Create a file with holes by writing to offset 0 (block #0) and
// offset 4096 (block #1).
func TestFileHoles(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/fileholes"
	file, err := os.Create(fn)
	if err != nil {
		t.Errorf("file create failed")
	}
	defer file.Close()
	foo := []byte("foo")
	file.Write(foo)
	file.WriteAt(foo, 4096)
	_, err = ioutil.ReadFile(fn)
	if err != nil {
		t.Error(err)
	}
}

func TestRmwRace(t *testing.T) {

	runtime.GOMAXPROCS(10)

	fn := test_helpers.DefaultPlainDir + "/rmwrace"
	f1, err := os.Create(fn)
	if err != nil {
		t.Fatalf("file create failed")
	}
	defer f1.Close()
	f2, err := os.Create(fn)
	if err != nil {
		t.Fatalf("file create failed")
	}
	defer f2.Close()

	oldBlock := bytes.Repeat([]byte("o"), 4096)

	newBlock := bytes.Repeat([]byte("n"), 4096)

	shortBlock := bytes.Repeat([]byte("s"), 16)

	mergedBlock := make([]byte, 4096)
	copy(mergedBlock, newBlock)
	copy(mergedBlock[4080:], shortBlock)

	goodMd5 := make(map[string]int)

	for i := 0; i < 1000; i++ {
		// Reset to [ooooooooo]
		_, err = f1.WriteAt(oldBlock, 0)
		if err != nil {
			t.Fatalf("Write failed")
		}

		var wg sync.WaitGroup
		wg.Add(2)

		// Write to the end of the file, [....ssss]
		go func() {
			f1.WriteAt(shortBlock, 4080)
			wg.Done()
		}()

		// Overwrite to [nnnnnnn]
		go func() {
			f2.WriteAt(newBlock, 0)
			wg.Done()
		}()

		wg.Wait()

		// The file should be either:
		// [nnnnnnnnnn] (md5: 6c1660fdabccd448d1359f27b3db3c99) or
		// [nnnnnnssss] (md5: da885006a6a284530a427c73ce1e5c32)
		// but it must not be
		// [oooooossss]

		buf, _ := ioutil.ReadFile(fn)
		m := test_helpers.Md5hex(buf)
		goodMd5[m] = goodMd5[m] + 1

		/*
			if m == "6c1660fdabccd448d1359f27b3db3c99" {
				fmt.Println(hex.Dump(buf))
				t.FailNow()
			}
		*/
	}
}

// With "--plaintextnames", the name "/gocryptfs.conf" is reserved.
// Otherwise there should be no restrictions.
func TestFiltered(t *testing.T) {
	filteredFile := test_helpers.DefaultPlainDir + "/gocryptfs.conf"
	file, err := os.Create(filteredFile)
	if testcase.plaintextnames && err == nil {
		t.Errorf("should have failed but didn't")
	} else if !testcase.plaintextnames && err != nil {
		t.Error(err)
	}
	file.Close()

	err = os.Remove(filteredFile)
	if testcase.plaintextnames && err == nil {
		t.Errorf("should have failed but didn't")
	} else if !testcase.plaintextnames && err != nil {
		t.Error(err)
	}
}

func TestFilenameEncryption(t *testing.T) {
	file, err := os.Create(test_helpers.DefaultPlainDir + "/TestFilenameEncryption.txt")
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(test_helpers.DefaultCipherDir + "/TestFilenameEncryption.txt")
	if testcase.plaintextnames && err != nil {
		t.Errorf("plaintextnames not working: %v", err)
	} else if !testcase.plaintextnames && err == nil {
		t.Errorf("file name encryption not working")
	}
}

// Test Rename
func TestRename(t *testing.T) {
	test_helpers.TestRename(t, test_helpers.DefaultPlainDir)
}

// Test that names of all lengths work
func TestNameLengths(t *testing.T) {
	f, err := os.Open(test_helpers.DefaultPlainDir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := f.Readdirnames(0)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	cnt1 := len(entries)

	wd := test_helpers.DefaultPlainDir + "/"
	name := "x"
	for len(name) < 2000 {
		f, err := os.Create(wd + name + "x")
		if err != nil {
			break
		}
		name = name + "x"
		f.Close()
		f, err = os.Open(test_helpers.DefaultPlainDir)
		if err != nil {
			t.Fatal(err)
		}
		// In v1.7-rc2, we had a bug that allowed creation of too-long names.
		// This threw errors in like this in READDIR:
		//
		//   OpenDir ".": invalid entry "gocryptfs.longname.wrE-izsR9ciEkP7JSCFDrk_d_Nj4mQo1dGY6hjuixAU=":
		//   Could not read .name: ReadLongName: size=345 > limit=344
		//
		entries, err = f.Readdirnames(0)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		cnt2 := len(entries)
		if cnt2 != cnt1+1 {
			t.Fatalf("len=%d: expected %d dir entries, have %d: %v", len(name), cnt1+1, cnt2, entries)
		}
		err = syscall.Unlink(wd + name)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(name) != 255 {
		t.Errorf("maxlen=%d", len(name))
	}
}

func TestLongNames(t *testing.T) {
	fi, err := ioutil.ReadDir(test_helpers.DefaultCipherDir)
	if err != nil {
		t.Fatal(err)
	}
	cnt1 := len(fi)
	wd := test_helpers.DefaultPlainDir + "/"
	// Create file with long name
	n255x := string(bytes.Repeat([]byte("x"), 255))
	f, err := os.Create(wd + n255x)
	if err != nil {
		t.Fatalf("Could not create n255x: %v", err)
	}
	f.Close()
	if !test_helpers.VerifyExistence(t, wd+n255x) {
		t.Errorf("n255x is not in directory listing")
	}
	// Rename long to long (target does not exist)
	n255y := string(bytes.Repeat([]byte("y"), 255))
	err = os.Rename(wd+n255x, wd+n255y)
	if err != nil {
		t.Fatalf("Could not rename n255x to n255y: %v", err)
	}
	if !test_helpers.VerifyExistence(t, wd+n255y) {
		t.Errorf("n255y is not in directory listing")
	}
	// Rename long to long (target exists)
	f, err = os.Create(wd + n255x)
	if err != nil {
		t.Fatalf("Could not create n255x: %v", err)
	}
	f.Close()
	err = os.Rename(wd+n255x, wd+n255y)
	if err != nil {
		t.Fatalf("Could not rename n255x to n255y: %v", err)
	}
	if !test_helpers.VerifyExistence(t, wd+n255y) {
		t.Errorf("n255y is not in directory listing")
	}
	// Rename long to short (target does not exist)
	err = os.Rename(wd+n255y, wd+"short")
	if err != nil {
		t.Fatalf("Could not rename n255y to short: %v", err)
	}
	if !test_helpers.VerifyExistence(t, wd+"short") {
		t.Errorf("short is not in directory listing")
	}
	// Rename long to short (target exists)
	f, err = os.Create(wd + n255y)
	if err != nil {
		t.Fatalf("Could not create n255y: %v", err)
	}
	f.Close()
	err = os.Rename(wd+n255y, wd+"short")
	if err != nil {
		t.Fatalf("Could not rename n255y to short: %v", err)
	}
	if !test_helpers.VerifyExistence(t, wd+"short") {
		t.Errorf("short is not in directory listing")
	}
	// Rename short to long (target does not exist)
	err = os.Rename(wd+"short", wd+n255x)
	if err != nil {
		t.Fatalf("Could not rename short to n255x: %v", err)
	}
	if !test_helpers.VerifyExistence(t, wd+n255x) {
		t.Errorf("255x is not in directory listing II")
	}
	// Rename short to long (target exists)
	f, err = os.Create(wd + "short")
	if err != nil {
		t.Fatalf("Could not create short: %v", err)
	}
	f.Close()
	err = os.Rename(wd+"short", wd+n255x)
	if err != nil {
		t.Fatalf("Could not rename short to n255x: %v", err)
	}
	if !test_helpers.VerifyExistence(t, wd+n255x) {
		t.Errorf("n255x is not in directory listing")
	}
	// Unlink
	err = syscall.Unlink(wd + n255x)
	if err != nil {
		t.Fatalf("Could not unlink n255x: %v", err)
	}
	if test_helpers.VerifyExistence(t, wd+n255x) {
		t.Errorf("n255x still there after unlink")
	}
	// Long symlink
	n255s := string(bytes.Repeat([]byte("s"), 255))
	err = os.Symlink("/", wd+n255s)
	if err != nil {
		t.Fatal(err)
	}
	if !test_helpers.VerifyExistence(t, wd+n255s) {
		t.Errorf("n255s is not in directory listing")
	}
	err = syscall.Unlink(wd + n255s)
	if err != nil {
		t.Error(err)
	}
	// Long dir
	n255d := string(bytes.Repeat([]byte("d"), 255))
	err = os.Mkdir(wd+n255d, 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Rmdir(wd + n255d)
	if err != nil {
		t.Error(err)
	}
	// Check for orphaned files
	fi, err = ioutil.ReadDir(test_helpers.DefaultCipherDir)
	if err != nil {
		t.Fatal(err)
	}
	cnt2 := len(fi)
	if cnt1 != cnt2 {
		t.Errorf("Leftover files, cnt1=%d cnt2=%d", cnt1, cnt2)
	}
}

// Create hard link with long name.
// This was broken up to v1.2.
func TestLongLink(t *testing.T) {
	wd := test_helpers.DefaultPlainDir + "/"
	target := wd + "TestLongLink.target"
	f, err := os.Create(target)
	if err != nil {
		t.Fatalf("%v", err)
	}
	f.Close()
	l255 := string(bytes.Repeat([]byte("l"), 255))
	err = os.Link(target, wd+l255)
	if err != nil {
		t.Error(err)
	}
}

func TestLchown(t *testing.T) {
	name := test_helpers.DefaultPlainDir + "/symlink"
	err := os.Symlink("/target/does/not/exist", name)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Chown(name, os.Getuid(), os.Getgid())
	if err == nil {
		t.Error("Chown on dangling symlink should fail")
	}
	err = os.Lchown(name, os.Getuid(), os.Getgid())
	if err != nil {
		t.Error(err)
	}
}

// Set nanoseconds by path, symlink
func TestUtimesNanoSymlink(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skipf("MacOS \"touch\" does not support \"--no-dereference\"")
	}
	path := test_helpers.DefaultPlainDir + "/utimesnano_symlink"
	err := os.Symlink("/some/nonexisting/file", path)
	if err != nil {
		t.Fatal(err)
	}
	// syscall.UtimesNano does not provide a way to pass AT_SYMLINK_NOFOLLOW,
	// so we call the external utility "touch", which does.
	cmd := exec.Command("touch", "--no-dereference", path)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	if err != nil {
		t.Error(err)
	}
}

type utimesTestcaseStruct struct {
	// Input atime and mtime
	in [2]syscall.Timespec
	// Expected output atime and mtime
	out [2]syscall.Timespec
}

// compareTimespec return true if the two passed Timespec are identical.
func compareTimespec(want syscall.Timespec, actual syscall.Timespec) bool {
	if want.Sec != actual.Sec {
		return false
	}
	if want.Nsec != actual.Nsec {
		return false
	}
	return true
}

const _UTIME_OMIT = ((1 << 30) - 2)

// doTestUtimesNano verifies that setting nanosecond-precision times on "path"
// works correctly. Pass "/proc/self/fd/N" to test a file descriptor.
func doTestUtimesNano(t *testing.T, path string) {
	utimeTestcases := []utimesTestcaseStruct{
		{
			in:  [2]syscall.Timespec{{Sec: 50, Nsec: 0}, {Sec: 51, Nsec: 0}},
			out: [2]syscall.Timespec{{Sec: 50, Nsec: 0}, {Sec: 51, Nsec: 0}},
		},
		{
			in:  [2]syscall.Timespec{{Sec: 1, Nsec: 2}, {Sec: 3, Nsec: 4}},
			out: [2]syscall.Timespec{{Sec: 1, Nsec: 2}, {Sec: 3, Nsec: 4}},
		},
		{
			in:  [2]syscall.Timespec{{Sec: 7, Nsec: 8}, {Sec: 99, Nsec: _UTIME_OMIT}},
			out: [2]syscall.Timespec{{Sec: 7, Nsec: 8}, {Sec: 3, Nsec: 4}},
		},
		{
			in:  [2]syscall.Timespec{{Sec: 99, Nsec: _UTIME_OMIT}, {Sec: 5, Nsec: 6}},
			out: [2]syscall.Timespec{{Sec: 7, Nsec: 8}, {Sec: 5, Nsec: 6}},
		},
	}
	if runtime.GOOS == "darwin" {
		// darwin neither supports UTIME_OMIT nor nanoseconds (!?)
		utimeTestcases = utimeTestcases[:1]
	}
	for i, tc := range utimeTestcases {
		err := syscall.UtimesNano(path, tc.in[:])
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		var st syscall.Stat_t
		err = syscall.Stat(path, &st)
		if err != nil {
			t.Fatal(err)
		}
		want := tc.out
		have := extractAtimeMtime(st)
		if !compareTimespec(want[0], have[0]) {
			t.Errorf("Testcase %d: atime: want=%+v, have=%+v", i, want[0], have[0])
		}
		if !compareTimespec(want[1], have[1]) {
			t.Errorf("Testcase %d: mtime: want=%+v, have=%+v", i, want[1], have[1])
		}
	}
}

// Set nanoseconds by path, normal file
func TestUtimesNano(t *testing.T) {
	path := test_helpers.DefaultPlainDir + "/utimesnano"
	err := ioutil.WriteFile(path, []byte("foobar"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	doTestUtimesNano(t, path)
}

// Set nanoseconds by fd
func TestUtimesNanoFd(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skipf("MacOS does not have /proc")
	}
	path := test_helpers.DefaultPlainDir + "/utimesnanofd"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	procPath := fmt.Sprintf("/proc/self/fd/%d", f.Fd())
	doTestUtimesNano(t, procPath)
}

// Make sure the Mknod call works by creating a fifo (named pipe)
func TestMkfifo(t *testing.T) {
	path := test_helpers.DefaultPlainDir + "/fifo1"
	err := syscall.Mkfifo(path, 0700)
	if err != nil {
		t.Fatal(err)
	}
	path = test_helpers.DefaultPlainDir + "/gocryptfs.longname.XXX"
	err = syscall.Mkfifo(path, 0700)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Remove(path)
	if err != nil {
		t.Fatal(err)
	}
}

// TestMagicNames verifies that "magic" names are handled correctly
// https://github.com/rfjakob/gocryptfs/issues/174
func TestMagicNames(t *testing.T) {
	names := []string{"warmup1", "warmup2", "gocryptfs.longname.QhUr5d9FHerwEs--muUs6_80cy6JRp89c1otLwp92Cs", "gocryptfs.diriv"}
	for _, n := range names {
		t.Logf("Testing n=%q", n)
		p := test_helpers.DefaultPlainDir + "/" + n
		// Create file
		err := ioutil.WriteFile(p, []byte("xxxxxxx"), 0200)
		if err != nil {
			t.Fatalf("creating file %q failed: %v", n, err)
		}
		// Rename magic to normal
		err = os.Rename(p, test_helpers.DefaultPlainDir+"/x")
		if err != nil {
			t.Fatalf("rename 1 failed: %v", err)
		}
		// Rename normal to magic
		err = os.Rename(test_helpers.DefaultPlainDir+"/x", p)
		if err != nil {
			t.Fatalf("rename 2 failed: %v", err)
		}
		// Unlink
		err = syscall.Unlink(p)
		if err != nil {
			t.Fatal(err)
		}
		// Mkdir
		err = os.Mkdir(p, 0700)
		if err != nil {
			t.Fatal(err)
		}
		// Rmdir
		err = syscall.Rmdir(p)
		if err != nil {
			t.Fatal(err)
		}
		// Symlink
		err = syscall.Symlink("xxxyyyyzzz", p)
		if err != nil {
			t.Fatal(err)
		}
		syscall.Unlink(p)
		// Link
		target := test_helpers.DefaultPlainDir + "/linktarget"
		err = ioutil.WriteFile(target, []byte("yyyyy"), 0600)
		if err != nil {
			t.Fatal(err)
		}
		err = syscall.Link(target, p)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Test that chmod works correctly
func TestChmod(t *testing.T) {
	path := test_helpers.DefaultPlainDir + "/" + t.Name()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	modes := []os.FileMode{0777, 0707, 0606, 0666, 0444, 0000, 0111, 0123, 0321}
	for _, modeWant := range modes {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		err = syscall.Chmod(path, uint32(modeWant))
		if err != nil {
			t.Errorf("chmod %03o -> %03o failed: %v", fi.Mode(), modeWant, err)
			continue
		}
		fi, err = os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		modeHave := fi.Mode()
		if modeHave != modeWant {
			t.Errorf("modeHave %#o != modeWant %#o", modeHave, modeWant)
		}
	}
}

// Test that access(2) works correctly
func TestAccess(t *testing.T) {
	path := test_helpers.DefaultPlainDir + "/" + t.Name()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	err = unix.Access(path, unix.F_OK)
	if err != nil {
		t.Error(err)
	}
	err = unix.Access(path, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	err = unix.Access(path, unix.X_OK)
	if err == nil {
		t.Error("X_OK should have failed")
	}
}

func TestStatfs(t *testing.T) {
	var st syscall.Statfs_t
	syscall.Statfs(test_helpers.DefaultPlainDir, &st)
	if st.Bsize == 0 {
		t.Errorf("statfs reports size zero: %#v", st)
	}
}

// gocryptfs 2.0 reported the ciphertext size on symlink creation, causing
// confusion: https://github.com/rfjakob/gocryptfs/issues/574
func TestSymlinkSize(t *testing.T) {
	p := filepath.Join(test_helpers.DefaultPlainDir, t.Name())
	// SYMLINK reports the size to the kernel
	if err := syscall.Symlink("foo", p); err != nil {
		t.Fatal(err)
	}
	// Kernel serves us this value from the attr cache
	var st syscall.Stat_t
	if err := syscall.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	if st.Size != 3 {
		t.Errorf("wrong size: have %d, want %d", st.Size, 3)
	}
}

// TestPwd check that /usr/bin/pwd works inside gocryptfs.
//
// This was broken in gocryptfs v2.0 with -sharedstorage:
// https://github.com/rfjakob/gocryptfs/issues/584
func TestPwd(t *testing.T) {
	dir := test_helpers.DefaultPlainDir
	for i := 0; i < 3; i++ {
		cmd := exec.Command("pwd")
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Log(strings.TrimSpace(string(out)))
			t.Fatalf("dir %q: %v", dir, err)
		}
		dir = dir + "/" + t.Name()
		os.Mkdir(dir, 0700)
	}
}
