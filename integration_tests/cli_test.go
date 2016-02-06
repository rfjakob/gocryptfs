package integration_tests

// Test CLI operations like "-init", "-password" etc

import (
	"os"
	"os/exec"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

// Test -init flag
func TestInit(t *testing.T) {
	dir := tmpDir + "TestInit/"
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gocryptfsBinary, "-init", "-extpass", "echo test", "-scryptn=10", dir)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(dir + configfile.ConfDefaultName)
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
		"-config", config, "-scryptn=10", dir)
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

// Test -init -plaintextnames
func TestInitPlaintextNames(t *testing.T) {
	dir := tmpDir + "TestInitPlaintextNames/"
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gocryptfsBinary, "-init", "-extpass", "echo test",
		"-scryptn=10", "-plaintextnames", dir)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(dir + configfile.ConfDefaultName)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(dir + nametransform.DirIVFilename)
	if err == nil {
		t.Errorf("gocryptfs.diriv should not have been created with -plaintextnames")
	}
	_, cf, err := configfile.LoadConfFile(dir+configfile.ConfDefaultName, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !cf.IsFeatureFlagSet(configfile.FlagPlaintextNames) {
		t.Error("PlaintextNames flag should be set but isnt")
	}
	if cf.IsFeatureFlagSet(configfile.FlagEMENames) || cf.IsFeatureFlagSet(configfile.FlagDirIV) {
		t.Error("FlagEMENames and FlagDirIV should be not set")
	}
}
