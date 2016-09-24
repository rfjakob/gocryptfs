package reverse_test

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

var dirA, dirB, x240 string

func TestMain(m *testing.M) {
	x240 = string(bytes.Repeat([]byte("x"), 240))
	dirA = test_helpers.TmpDir + "/a"
	dirB = test_helpers.TmpDir + "/b"
	os.Mkdir(dirA, 0700)
	os.Mkdir(dirB, 0700)
	generateFiles(dirA)
	test_helpers.MountOrExit(dirA, dirB, "-zerokey", "-reverse")
	r := m.Run()
	test_helpers.UnmountPanic(dirB)
	os.RemoveAll(test_helpers.TmpDir)
	os.Exit(r)
}

func genName(i int) string {
	return fmt.Sprintf("%04d.%s", i, x240)
}

// Create 10000 files with long names
func generateFiles(dir string) {
	for i := 0; i < 100000; i++ {
		n := genName(i)
		f, err := os.Create(dir + "/" + n)
		if err != nil {
			panic(err)
		}
		f.Close()
	}
}

func TestLongnameStat(t *testing.T) {
	_, err := os.Stat(dirA + "/" + genName(0))
	if err != nil {
		t.Error(err)
	}
	_, err = os.Stat(dirA + "/" + genName(9999))
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkLongnameStat(b *testing.B) {
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := os.Stat(dirB + "/" + encryptedNames[i%l])
		if err != nil {
			b.Fatal(err)
		}
	}
}
