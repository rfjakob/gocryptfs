package reverse_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

var dirA, dirB, dirC string
var x240 string

func TestMain(m *testing.M) {
	x240 = string(bytes.Repeat([]byte("x"), 240))
	dirA = test_helpers.TmpDir + "/a"
	dirB = test_helpers.TmpDir + "/b"
	dirC = test_helpers.TmpDir + "/c"
	if err := os.Mkdir(dirA, 0700); err != nil {
		panic(err)
	}
	if err := os.Mkdir(dirB, 0700); err != nil {
		panic(err)
	}
	if err := os.Mkdir(dirC, 0700); err != nil {
		panic(err)
	}
	test_helpers.MountOrExit(dirA, dirB, "-zerokey", "-reverse")
	test_helpers.MountOrExit(dirB, dirC, "-zerokey", "-aessiv")
	r := m.Run()
	test_helpers.UnmountPanic(dirC)
	test_helpers.UnmountPanic(dirB)
	os.RemoveAll(test_helpers.TmpDir)
	os.Exit(r)
}
