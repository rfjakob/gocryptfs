// Tests run for (almost all) combinations of openssl, aessiv, plaintextnames.
//
// File reading, writing, modification, truncate, ...
//
// Runs all tests N times, for the combinations of different flags specified
// in the `matrix` variable.

package matrix

import (
	"flag"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// Several tests need to be aware if plaintextnames is active or not, so make this
// a global variable
var testcase testcaseMatrix

type testcaseMatrix struct {
	plaintextnames bool
	openssl        string
	aessiv         bool
	raw64          bool
	extraArgs      []string
}

// isSet finds out if `extraArg` is set in `tc.extraArgs`
func (tc *testcaseMatrix) isSet(extraArg string) bool {
	for _, v := range tc.extraArgs {
		if v == extraArg {
			return true
		}
	}
	return false
}

// This is the entry point for the tests
func TestMain(m *testing.M) {
	var matrix = []testcaseMatrix{
		// Normal
		{false, "auto", false, false, nil},
		{false, "true", false, false, nil},
		{false, "false", false, false, nil},
		// Plaintextnames
		{true, "true", false, false, nil},
		{true, "false", false, false, nil},
		// AES-SIV (does not use openssl, no need to test permutations)
		{false, "auto", true, false, nil},
		{true, "auto", true, false, nil},
		// Raw64
		{false, "auto", false, true, nil},
		// -serialize_reads
		{false, "auto", false, false, []string{"-serialize_reads"}},
		{false, "auto", false, false, []string{"-sharedstorage"}},
		{false, "auto", false, false, []string{"-deterministic-names"}},
		// Test xchacha with and without openssl
		{false, "true", false, true, []string{"-xchacha"}},
		{false, "false", false, true, []string{"-xchacha"}},
	}

	// Make "testing.Verbose()" return the correct value
	flag.Parse()
	var i int
	for i, testcase = range matrix {
		if testcase.openssl == "true" && stupidgcm.BuiltWithoutOpenssl {
			continue
		}
		if testing.Verbose() {
			fmt.Printf("matrix: testcase = %#v\n", testcase)
		}
		createDirIV := true
		if testcase.plaintextnames {
			createDirIV = false
		} else if testcase.isSet("-deterministic-names") {
			createDirIV = false
		}
		test_helpers.ResetTmpDir(createDirIV)
		opts := []string{"-zerokey"}
		//opts = append(opts, "-fusedebug")
		opts = append(opts, fmt.Sprintf("-openssl=%v", testcase.openssl))
		opts = append(opts, fmt.Sprintf("-plaintextnames=%v", testcase.plaintextnames))
		opts = append(opts, fmt.Sprintf("-aessiv=%v", testcase.aessiv))
		opts = append(opts, fmt.Sprintf("-raw64=%v", testcase.raw64))
		opts = append(opts, testcase.extraArgs...)
		test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, opts...)
		before := test_helpers.ListFds(0, test_helpers.TmpDir)
		t0 := time.Now()
		r := m.Run()
		if testing.Verbose() {
			fmt.Printf("matrix: run took %v\n", time.Since(t0))
		}
		// Catch fd leaks in the tests. NOTE: this does NOT catch leaks in
		// the gocryptfs FUSE process, but only in the tests that access it!
		// All fds that point outside TmpDir are not interesting (the Go test
		// infrastucture creates temporary log files we don't care about).
		after := test_helpers.ListFds(0, test_helpers.TmpDir)
		if len(before) != len(after) {
			fmt.Printf("fd leak in test process? before, after:\n%v\n%v\n", before, after)
			os.Exit(1)
		}
		test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
		if r != 0 {
			fmt.Printf("TestMain: matrix[%d] = %#v failed\n", i, testcase)
			os.Exit(r)
		}
	}
	os.Exit(0)
}
