package reverse_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

var x240 = string(bytes.Repeat([]byte("x"), 240))
var plaintextnames bool

// dirA is a normal directory
var dirA string

// dirB is the reverse mount backed by dirA
var dirB string

// dirC is a forward mount backed by dirB
var dirC string

// Create directory "dirA", mount it reverse to "dirB", mount it forward
// to "dirC".
func TestMain(m *testing.M) {
	var r int
	for _, plaintextnames = range []bool{false, true} {
		argsA := []string{"-reverse"}
		if plaintextnames {
			argsA = append(argsA, "-plaintextnames")
		}
		dirA = test_helpers.InitFS(nil, argsA...)
		dirB = test_helpers.TmpDir + "/b"
		dirC = test_helpers.TmpDir + "/c"
		if err := os.Mkdir(dirB, 0700); err != nil {
			panic(err)
		}
		if err := os.Mkdir(dirC, 0700); err != nil {
			panic(err)
		}
		test_helpers.MountOrExit(dirA, dirB, "-reverse", "-extpass", "echo test")
		test_helpers.MountOrExit(dirB, dirC, "-extpass", "echo test")
		r = m.Run()
		test_helpers.UnmountPanic(dirC)
		test_helpers.UnmountPanic(dirB)

		os.RemoveAll(dirA)
		os.RemoveAll(dirB)
		os.RemoveAll(dirC)

		if r != 0 {
			os.Exit(r)
		}
	}
	os.Exit(r)
}
