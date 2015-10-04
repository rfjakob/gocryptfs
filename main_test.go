package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"
)

const tmpDir = "main_test_tmp/"
const plainDir = tmpDir + "plain/"
const cipherDir = tmpDir + "cipher/"

func unmount() error {
	fu := exec.Command("fusermount", "-z", "-u", plainDir)
	fu.Stdout = os.Stdout
	fu.Stderr = os.Stderr
	return fu.Run()
}

func md5fn(filename string) string {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("ReadFile: %v\n", err)
		return ""
	}
	rawHash := md5.Sum(buf)
	hash := hex.EncodeToString(rawHash[:])
	return hash
}

func TestMain(m *testing.M) {

	unmount()
	os.RemoveAll(tmpDir)

	err := os.MkdirAll(plainDir, 0777)
	if err != nil {
		panic("Could not create plainDir")
	}

	err = os.MkdirAll(cipherDir, 0777)
	if err != nil {
		panic("Could not create cipherDir")
	}

	//c := exec.Command("./gocryptfs", "--zerokey", "--cpuprofile", "/tmp/gcfs.cpu", cipherDir, plainDir)
	c := exec.Command("./gocryptfs", "--zerokey", cipherDir, plainDir)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	go c.Run()

	time.Sleep(3 * time.Second)

	r := m.Run()

	unmount()
	os.Exit(r)
}

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

	bin := md5.Sum(d)
	hashWant := hex.EncodeToString(bin[:])

	hashActual := md5fn(plainDir + fn)

	if hashActual != hashWant {
		fmt.Printf("hashWant=%s hashActual=%s\n", hashWant, hashActual)
		t.Fail()
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
	if md5fn(fn) != "95d4ec7038e3e4fdbd5f15c34c3f0b34" {
		t.Fail()
	}
	// Shrink - needs RMW
	file.Truncate(6999)
	if md5fn(fn) != "35fd15873ec6c35380064a41b9b9683b" {
		t.Fail()
	}
	// Shrink to one partial block
	file.Truncate(465)
	if md5fn(fn) != "a1534d6e98a6b21386456a8f66c55260" {
		t.Fail()
	}
	// Grow to exactly one block
	file.Truncate(4096)
	if md5fn(fn) != "620f0b67a91f7f74151bc5be745b7110" {
		t.Fail()
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
		fmt.Printf("Growing file to %d MB... ", t.N)
		f2, err := os.OpenFile(fn, os.O_WRONLY | os.O_APPEND, 0666)
		if err != nil {
			fmt.Println(err)
			t.FailNow()
		}
		for h := 0; h < t.N - mb ; h++ {
			_, err = f2.Write(buf)
			if err != nil {
				fmt.Println(err)
				t.FailNow()
			}
		}
		f2.Close()
		fmt.Printf("done\n")
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
