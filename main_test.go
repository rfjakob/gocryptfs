package main

import (
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
	fu := exec.Command("fusermount", "-u", plainDir)
	fu.Stdout = os.Stdout
	fu.Stderr = os.Stderr
	return fu.Run()
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

	buf, err := ioutil.ReadFile(plainDir + fn)
	if err != nil {
		t.Fail()
	}

	raw := md5.Sum(d)
	hashWant := hex.EncodeToString(raw[:])

	raw = md5.Sum(buf)
	hashActual := hex.EncodeToString(raw[:])
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
		buf, err := ioutil.ReadFile(plainDir + "1M")
		if err != nil {
			t.Fail()
		}
		rawHash := md5.Sum(buf)
		hashActual := hex.EncodeToString(rawHash[:])
		if hashActual != hashWant {
			fmt.Printf("Read corruption in loop # %d\n", i)
			t.FailNow()
		} else {
			//fmt.Print(".")
		}
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
