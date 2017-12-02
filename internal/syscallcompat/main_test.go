package syscallcompat

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

var tmpDir string
var tmpDirFd int

func TestMain(m *testing.M) {
	origWd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	parent := "/tmp/gocryptfs-test-parent"
	err = os.MkdirAll(parent, 0700)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	tmpDir, err = ioutil.TempDir(parent, "syscallcompat")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dirf, err := os.Open(tmpDir)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer dirf.Close()
	tmpDirFd = int(dirf.Fd())
	// Run the tests
	r := m.Run()
	// Check that we are in the same directory again (the emulated syscalls
	// use Fchdir a lot)
	cwd, _ := os.Getwd()
	if cwd != origWd {
		fmt.Printf("working dir has changed from %q to %q", origWd, cwd)
		os.Exit(1)
	}
	os.Exit(r)
}
