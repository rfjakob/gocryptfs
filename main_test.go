package main

import (
	"runtime"
	"sync"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
)

const tmpDir = "/tmp/gocryptfs_main_test/"
const plainDir = tmpDir + "plain/"
const cipherDir = tmpDir + "cipher/"

func mount(extraArgs ...string) {
	var args []string
	args = append(args, extraArgs...)
	//args = append(args, "--fusedebug")
	args = append(args, cipherDir)
	args = append(args, plainDir)
	c := exec.Command("./gocryptfs", args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	err := c.Run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func unmount() error {
	fu := exec.Command("fusermount", "-z", "-u", plainDir)
	fu.Stdout = os.Stdout
	fu.Stderr = os.Stderr
	return fu.Run()
}

// Return md5 string for file "filename"
func md5fn(filename string) string {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("ReadFile: %v\n", err)
		return ""
	}
	return md5hex(buf)
}

// Return md5 string for "buf"
func md5hex(buf []byte) string {
	rawHash := md5.Sum(buf)
	hash := hex.EncodeToString(rawHash[:])
	return hash
}

// Verify that the file size equals "want". This checks:
// 1) Size reported by Stat()
// 2) Number of bytes returned when reading the whole file
func verifySize(t *testing.T, path string, want int) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		t.Errorf("ReadFile failed: %v", err)
	} else if len(buf) != want {
		t.Errorf("wrong read size: got=%d want=%d", len(buf), want)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Errorf("Stat failed: %v", err)
	} else if fi.Size() != int64(want) {
		t.Errorf("wrong stat file size, got=%d want=%d", fi.Size(), want)
	}
}

// This is the entry point for the tests
func TestMain(m *testing.M) {

	fu := exec.Command("fusermount", "-z", "-u", plainDir)
	fu.Run()

	os.RemoveAll(tmpDir)

	err := os.MkdirAll(plainDir, 0777)
	if err != nil {
		panic("Could not create plainDir")
	}

	err = os.MkdirAll(cipherDir, 0777)
	if err != nil {
		panic("Could not create cipherDir")
	}

	mount("--zerokey", "--openssl=false")
	r := m.Run()
	unmount()

	mount("--zerokey")
	r = m.Run()
	unmount()

	os.Exit(r)
}

// Write "n" zero bytes to filename "fn", read again, compare hash
func testWriteN(t *testing.T, fn string, n int) string {
	file, err := os.Create(plainDir + fn)
	if err != nil {
		t.FailNow()
	}

	d := make([]byte, n)
	written, err := file.Write(d)
	if err != nil || written != len(d) {
		fmt.Printf("err=\"%s\", written=%d\n", err, written)
		t.Fail()
	}
	file.Close()

	verifySize(t, plainDir + fn, n)

	bin := md5.Sum(d)
	hashWant := hex.EncodeToString(bin[:])

	hashActual := md5fn(plainDir + fn)

	if hashActual != hashWant {
		t.Errorf("Wrong content, hashWant=%s hashActual=%s\n", hashWant, hashActual)
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

func TestWrite1Mx100(t *testing.T) {
	hashWant := testWriteN(t, "1Mx100", 1024*1024)
	// Read and check 100 times to catch race conditions
	var i int
	for i = 0; i < 100; i++ {
		hashActual := md5fn(plainDir + "1M")
		if hashActual != hashWant {
			fmt.Printf("Read corruption in loop # %d\n", i)
			t.FailNow()
		} else {
			//fmt.Print(".")
		}
	}
}

func TestTruncate(t *testing.T) {
	fn := plainDir + "truncate"
	file, err := os.Create(fn)
	if err != nil {
		t.FailNow()
	}
	// Grow to two blocks
	file.Truncate(7000)
	verifySize(t, fn, 7000)
	if md5fn(fn) != "95d4ec7038e3e4fdbd5f15c34c3f0b34" {
		t.Errorf("wrong content")
	}
	// Shrink - needs RMW
	file.Truncate(6999)
	verifySize(t, fn, 6999)
	if md5fn(fn) != "35fd15873ec6c35380064a41b9b9683b" {
		t.Errorf("wrong content")
	}
	// Shrink to one partial block
	file.Truncate(465)
	verifySize(t, fn, 465)
	if md5fn(fn) != "a1534d6e98a6b21386456a8f66c55260" {
		t.Errorf("wrong content")
	}
	// Grow to exactly one block
	file.Truncate(4096)
	verifySize(t, fn, 4096)
	if md5fn(fn) != "620f0b67a91f7f74151bc5be745b7110" {
		t.Errorf("wrong content")
	}
}

func TestAppend(t *testing.T) {
	fn := plainDir + "append"
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
		hashActual := md5fn(fn)
		if hashWant != hashActual {
			t.FailNow()
		}
	}

	// Overwrite with the same data
	// Hash must stay the same
	file.Seek(0, 0)
	for i := 0; i <= 500; i++ {
		file.Write(data)
		hashActual := md5fn(fn)
		if hashWant != hashActual {
			t.FailNow()
		}
	}
}

// Create a file with holes by writing to offset 0 (block #0) and
// offset 4096 (block #1).
func TestFileHoles(t *testing.T) {
	fn := plainDir + "fileholes"
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

	fn := plainDir + "rmwrace"
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
		m := md5hex(buf)
		goodMd5[m] = goodMd5[m] + 1

		/*
		if m == "6c1660fdabccd448d1359f27b3db3c99" {
			fmt.Println(hex.Dump(buf))
			t.FailNow()
		}
		*/
	}
	fmt.Println(goodMd5)
}
func BenchmarkStreamWrite(t *testing.B) {
	buf := make([]byte, 1024*1024)
	t.SetBytes(int64(len(buf)))

	file, err := os.Create(plainDir + "BenchmarkWrite")
	if err != nil {
		t.FailNow()
	}

	t.ResetTimer()
	var i int
	for i = 0; i < t.N; i++ {
		written, err := file.Write(buf)
		if err != nil {
			fmt.Printf("err=\"%s\", written=%d\n", err.Error(), written)
			t.FailNow()
		}
	}
	file.Close()
}

func BenchmarkStreamRead(t *testing.B) {
	buf := make([]byte, 1024*1024)
	t.SetBytes(int64(len(buf)))

	fn := plainDir + "BenchmarkWrite"
	fi, _ := os.Stat(fn)
	mb := int(fi.Size() / 1024 / 1024)

	if t.N > mb {
		// Grow file so we can satisfy the test
		//fmt.Printf("Growing file to %d MB... ", t.N)
		f2, err := os.OpenFile(fn, os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Println(err)
			t.FailNow()
		}
		for h := 0; h < t.N-mb; h++ {
			_, err = f2.Write(buf)
			if err != nil {
				fmt.Println(err)
				t.FailNow()
			}
		}
		f2.Close()
		//fmt.Printf("done\n")
	}

	file, err := os.Open(plainDir + "BenchmarkWrite")
	if err != nil {
		t.FailNow()
	}
	t.ResetTimer()
	var i int
	for i = 0; i < t.N; i++ {
		_, err := file.Read(buf)
		if err == io.EOF {
			fmt.Printf("Test file too small\n")
			t.SkipNow()
		} else if err != nil {
			fmt.Println(err)
			t.FailNow()
		}
	}
	file.Close()
}
