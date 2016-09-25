package reverse_test

import (
	"fmt"
	"os"
	"testing"
)

func genName(i int, postfix string) string {
	return fmt.Sprintf("%04d.%s", i, postfix)
}

// Create 10000 files with long names
func generateLongnameFiles(dir string) {
	for i := 0; i < 100000; i++ {
		n := genName(i, x240)
		f, err := os.Create(dir + "/" + n)
		if err != nil {
			panic(err)
		}
		f.Close()
	}
}

func BenchmarkLongnameStat(b *testing.B) {
	// Setup
	generateLongnameFiles(dirA)
	dirFd, err := os.Open(dirB)
	if err != nil {
		b.Fatal(err)
	}
	encryptedNames, err := dirFd.Readdirnames(-1)
	if err != nil {
		b.Fatal(err)
	}
	l := len(encryptedNames)
	dirFd.Close()
	// Benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := os.Stat(dirB + "/" + encryptedNames[i%l])
		if err != nil {
			b.Fatal(err)
		}
	}
	// Cleanup
	b.StopTimer()
	os.RemoveAll(dirA)
	os.Mkdir(dirA, 0700)
}
