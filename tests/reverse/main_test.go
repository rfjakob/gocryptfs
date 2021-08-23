package reverse_test

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

var x240 = string(bytes.Repeat([]byte("x"), 240))

// plaintextnames is true when the currently running test has -plaintextnames active
var plaintextnames bool

// deterministic_names is true when the currently running test has -deterministic-names active
var deterministic_names bool

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

	testcases := []struct {
		plaintextnames      bool
		deterministic_names bool
	}{
		{false, false},
		{true, false},
		{false, true},
	}
	for i, tc := range testcases {
		argsA := []string{"-reverse"}
		plaintextnames, deterministic_names = tc.plaintextnames, tc.deterministic_names
		if tc.plaintextnames {
			argsA = append(argsA, "-plaintextnames")
		} else if tc.deterministic_names {
			argsA = append(argsA, "-deterministic-names")
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
			fmt.Printf("testcases[%d] = %#v failed\n", i, tc)
			os.Exit(r)
		}
	}
	os.Exit(r)
}
