package integration_tests

// Test CLI operations like "-init", "-password" etc

import (
	"os"
	"os/exec"
	"testing"

	"github.com/rfjakob/gocryptfs/cryptfs"
)

// Test -init flag
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
		t.Fatal(err)
	}
	_, err = os.Stat(dir + cryptfs.ConfDefaultName)
	if err != nil {
		t.Fatal(err)
	}

	// Test -passwd
	cmd2 := exec.Command(gocryptfsBinary, "-passwd", "-extpass", "echo test", dir)
	if testing.Verbose() {
		cmd2.Stdout = os.Stdout
		cmd2.Stderr = os.Stderr
	}
	err = cmd2.Run()
	if err != nil {
		t.Error(err)
	}
}

// Test -init & -config flag
func TestInitConfig(t *testing.T) {
	dir := tmpDir + "TestInitConfig/"
	config := tmpDir + "TestInitConfig.conf"
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gocryptfsBinary, "-init", "-extpass", "echo test",
		"-config", config, dir)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}

	// Test -passwd & -config
	cmd2 := exec.Command(gocryptfsBinary, "-passwd", "-extpass", "echo test",
		"-config", config, dir)
	if testing.Verbose() {
		cmd2.Stdout = os.Stdout
		cmd2.Stderr = os.Stderr
	}
	err = cmd2.Run()
	if err != nil {
		t.Error(err)
	}
}
