package integration_tests

import (
	"os"
	"os/exec"
	"fmt"
	"io"
	"testing"
)

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

func BenchmarkUntar(t *testing.B) {
	t.SetBytes(422229778)
	c := exec.Command("tar", "xf", "/tmp/linux-3.0.tar.gz", "-C", plainDir)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	t.ResetTimer()
	err := c.Run()
	if err != nil {
		t.Fatal(err)
	}
}
