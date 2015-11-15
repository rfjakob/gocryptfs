package integration_tests

// Test CLI operations like "-init", "-password" etc

import (
	"os"
	"os/exec"
	"testing"

	"github.com/rfjakob/gocryptfs/cryptfs"
)

func TestInit(t *testing.T) {
	dir := tmpDir + "TestInit/"
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gocryptfsBinary, "-init", "-extpass", "echo test", dir)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err = cmd.Run()
	if err != nil {
		t.Error(err)
	}
	_, err = os.Stat(dir + cryptfs.ConfDefaultName)
	if err != nil {
		t.Error(err)
	}
}

// "dir" has been initialized by TestInit
func TestPasswd(t *testing.T) {
	dir := tmpDir + "TestInit/"
	cmd := exec.Command(gocryptfsBinary, "-passwd", "-extpass", "echo test", dir)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err := cmd.Run()
	if err != nil {
		t.Error(err)
	}
}
