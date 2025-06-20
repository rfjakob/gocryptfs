package reverse_test

import (
	"bytes"
	"flag"
	"fmt"
	"log"
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

	flag.Parse()

	testcases := []struct {
		plaintextnames      bool
		deterministic_names bool
	}{
		{false, false},
		{true, false},
		{false, true},
	}
	for i, tc := range testcases {
		// Fill the global vars
		plaintextnames, deterministic_names = tc.plaintextnames, tc.deterministic_names
		if testing.Verbose() {
			log.Printf("TestMain: plaintextnames=%v deterministic_names=%v", plaintextnames, deterministic_names)
		}

		dirA, dirB, _ = newReverseFS(nil)
		dirC = test_helpers.TmpDir + "/c"
		if err := os.Mkdir(dirC, 0700); err != nil {
			panic(err)
		}
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

// newReverseFS creates and mounts a new, empty reverse filesystem.
func newReverseFS(extraMountArgs []string) (backingDir, mntDir, ctlsockPath string) {
	args := []string{"-reverse"}
	if plaintextnames {
		args = append(args, "-plaintextnames")
	} else if deterministic_names {
		args = append(args, "-deterministic-names")
	}
	backingDir = test_helpers.InitFS(nil, args...)
	mntDir = backingDir + ".mnt"
	ctlsockPath = mntDir + ".sock"
	mountArgs := []string{"-reverse", "-extpass", "echo test", "-ctlsock", ctlsockPath}
	mountArgs = append(mountArgs, extraMountArgs...)
	test_helpers.MountOrExit(backingDir, mntDir, mountArgs...)

	if testing.Verbose() {
		log.Printf("newReverseFS: mounted %q on %q", backingDir, mntDir)
	}
	return
}
