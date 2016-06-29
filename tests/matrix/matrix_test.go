package matrix

// File reading, writing, modification, truncate
//
// Runs everything four times, for all combinations of
// "-plaintextnames" and "-openssl".
//
// Test Matrix:
//                       openssl=true openssl=false
// plaintextnames=false  X            X
// plaintextnames=true   X            X

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sync"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

// Several tests need to be aware if plaintextnames is active or not, so make this
// a global variable
var plaintextnames bool

// This is the entry point for the tests
func TestMain(m *testing.M) {
	// Make "testing.Verbose()" return the correct value
	flag.Parse()
	for _, openssl := range []bool{true, false} {
		for _, plaintextnames = range []bool{true, false} {
			if testing.Verbose() {
				fmt.Printf("Testing openssl=%v plaintextnames=%v\n", openssl, plaintextnames)

			}
			test_helpers.ResetTmpDir(plaintextnames)
			opts := []string{"--zerokey"}
			opts = append(opts, fmt.Sprintf("-openssl=%v", openssl))
			opts = append(opts, fmt.Sprintf("-plaintextnames=%v", plaintextnames))
			test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, opts...)
			r := m.Run()
			test_helpers.Unmount(test_helpers.DefaultPlainDir)
			if r != 0 {
				os.Exit(r)
			}
		}
	}
	os.Exit(0)
}

// Write "n" zero bytes to filename "fn", read again, compare hash
func testWriteN(t *testing.T, fn string, n int) string {
	file, err := os.Create(test_helpers.DefaultPlainDir + "/" + fn)
	if err != nil {
		t.Fatal(err)
	}

	d := make([]byte, n)
	written, err := file.Write(d)
	if err != nil || written != len(d) {
		t.Errorf("err=\"%s\", written=%d", err, written)
	}
	err = file.Close()
	if err != nil {
		t.Error(err)
	}

	test_helpers.VerifySize(t, test_helpers.DefaultPlainDir+"/"+fn, n)

	bin := md5.Sum(d)
	hashWant := hex.EncodeToString(bin[:])

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
		hashActual := test_helpers.Md5fn(test_helpers.DefaultPlainDir + "/100")
		if hashActual != hashWant {
			fmt.Printf("Read corruption in loop #%d\n", i)
			t.FailNow()
		} else {
			//fmt.Print(".")
		}
	}
}

func TestTruncate(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/truncate"
	file, err := os.Create(fn)
	if err != nil {
		t.FailNow()
	}
	// Grow to two blocks
	file.Truncate(7000)
	test_helpers.VerifySize(t, fn, 7000)
	if test_helpers.Md5fn(fn) != "95d4ec7038e3e4fdbd5f15c34c3f0b34" {
		t.Errorf("wrong content")
	}
	// Shrink - needs RMW
	file.Truncate(6999)
	test_helpers.VerifySize(t, fn, 6999)
	if test_helpers.Md5fn(fn) != "35fd15873ec6c35380064a41b9b9683b" {
		t.Errorf("wrong content")
	}
	// Shrink to one partial block
	file.Truncate(465)
	test_helpers.VerifySize(t, fn, 465)
	if test_helpers.Md5fn(fn) != "a1534d6e98a6b21386456a8f66c55260" {
		t.Errorf("wrong content")
	}
	// Grow to exactly one block
	file.Truncate(4096)
	test_helpers.VerifySize(t, fn, 4096)
	if test_helpers.Md5fn(fn) != "620f0b67a91f7f74151bc5be745b7110" {
		t.Errorf("wrong content")
	}
}

func TestAppend(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/append"
	file, err := os.Create(fn)
	if err != nil {
		t.FailNow()
	}
	data := []byte("testdata123456789") // length 17
	var buf bytes.Buffer
	var hashWant string
	for i := 0; i <= 500; i++ {
		file.Write(data)
		buf.Write(data)
		bin := md5.Sum(buf.Bytes())
		hashWant = hex.EncodeToString(bin[:])
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
	foo := []byte("foo")
	file.Write(foo)
	file.WriteAt(foo, 4096)
	_, err = ioutil.ReadFile(fn)
	if err != nil {
		t.Error(err)
	}
}

// sContains - does the slice of strings "haystack" contain "needle"?
func sContains(haystack []string, needle string) bool {
	for _, element := range haystack {
		if element == needle {
			return true
		}
	}
	return false
}

func TestRmwRace(t *testing.T) {

	runtime.GOMAXPROCS(10)

	fn := test_helpers.DefaultPlainDir + "/rmwrace"
	f1, err := os.Create(fn)
	if err != nil {
		t.Fatalf("file create failed")
	}
	f2, err := os.Create(fn)
	if err != nil {
		t.Fatalf("file create failed")
	}

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
	if plaintextnames == true && err == nil {
		t.Errorf("should have failed but didn't")
	} else if plaintextnames == false && err != nil {
		t.Error(err)
	}
	file.Close()

	err = os.Remove(filteredFile)
	if plaintextnames == true && err == nil {
		t.Errorf("should have failed but didn't")
	} else if plaintextnames == false && err != nil {
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
	if plaintextnames == true && err != nil {
		t.Errorf("plaintextnames not working: %v", err)
	} else if plaintextnames == false && err == nil {
		t.Errorf("file name encryption not working")
	}
}

// Test Mkdir and Rmdir
func testMkdirRmdir(t *testing.T) {
	test_helpers.TestMkdirRmdir(t, test_helpers.DefaultPlainDir)
}

// Test Rename
func testRename(t *testing.T) {
	test_helpers.TestRename(t, test_helpers.DefaultPlainDir)
}

// Overwrite an empty directory with another directory
func TestDirOverwrite(t *testing.T) {
	dir1 := test_helpers.DefaultPlainDir + "/DirOverwrite1"
	dir2 := test_helpers.DefaultPlainDir + "/DirOverwrite2"
	err := os.Mkdir(dir1, 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Mkdir(dir2, 0777)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Rename(dir1, dir2)
	if err != nil {
		t.Fatal(err)
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
	if !test_helpers.VerifyExistence(wd + n255x) {
		t.Errorf("n255x is not in directory listing")
	}
	// Rename long to long
	n255y := string(bytes.Repeat([]byte("y"), 255))
	err = os.Rename(wd+n255x, wd+n255y)
	if err != nil {
		t.Fatalf("Could not rename n255x to n255y: %v", err)
	}
	if !test_helpers.VerifyExistence(wd + n255y) {
		t.Errorf("n255y is not in directory listing")
	}
	// Rename long to short
	err = os.Rename(wd+n255y, wd+"short")
	if err != nil {
		t.Fatalf("Could not rename n255y to short: %v", err)
	}
	if !test_helpers.VerifyExistence(wd + "short") {
		t.Errorf("short is not in directory listing")
	}
	// Rename short to long
	err = os.Rename(wd+"short", wd+n255x)
	if err != nil {
		t.Fatalf("Could not rename short to n255x: %v", err)
	}
	if !test_helpers.VerifyExistence(wd + n255x) {
		t.Errorf("255x is not in directory listing II")
	}
	// Unlink
	err = syscall.Unlink(wd + n255x)
	if err != nil {
		t.Fatalf("Could not unlink n255x: %v", err)
	}
	if test_helpers.VerifyExistence(wd + n255x) {
		t.Errorf("n255x still there after unlink")
	}
	// Long symlink
	n255s := string(bytes.Repeat([]byte("s"), 255))
	err = os.Symlink("/etc/motd", wd+n255s)
	if err != nil {
		t.Fatal(err)
	}
	if !test_helpers.VerifyExistence(wd + n255s) {
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
