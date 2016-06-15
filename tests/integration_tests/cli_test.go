package integration_tests

// Test CLI operations like "-init", "-password" etc

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/nametransform"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

// Test -init flag
func TestInit(t *testing.T) {
	dir, err := ioutil.TempDir(test_helpers.TmpDir, "TestInit")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-q", "-init", "-extpass", "echo test", "-scryptn=10", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(filepath.Join(dir, configfile.ConfDefaultName))
	if err != nil {
		t.Fatal(err)
	}
}

// Test -passwd flag
func TestPasswd(t *testing.T) {
	// Create FS
	dir, err := ioutil.TempDir(test_helpers.TmpDir, "TestPasswd")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-q", "-init", "-extpass", "echo test", "-scryptn=10", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}
	// Change password using "-extpass"
	cmd = exec.Command(test_helpers.GocryptfsBinary, "-q", "-passwd", "-extpass", "echo test", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		t.Error(err)
	}
	// Change password using stdin
	cmd = exec.Command(test_helpers.GocryptfsBinary, "-q", "-passwd", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	p, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Start()
	if err != nil {
		t.Error(err)
	}
	// Old password
	p.Write([]byte("test\n"))
	// New password
	p.Write([]byte("newpasswd\n"))
	p.Close()
	err = cmd.Wait()
	if err != nil {
		t.Error(err)
	}
}

// Test -init & -config flag
func TestInitConfig(t *testing.T) {
	dir := test_helpers.TmpDir + "TestInitConfig/"
	config := test_helpers.TmpDir + "TestInitConfig.conf"
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-q", "-init", "-extpass", "echo test",
		"-config", config, "-scryptn=10", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}

	// Test -passwd & -config
	cmd2 := exec.Command(test_helpers.GocryptfsBinary, "-q", "-passwd", "-extpass", "echo test",
		"-config", config, dir)
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	err = cmd2.Run()
	if err != nil {
		t.Error(err)
	}
}

// Test -init -plaintextnames
func TestInitPlaintextNames(t *testing.T) {
	dir := test_helpers.TmpDir + "TestInitPlaintextNames/"
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-q", "-init", "-extpass", "echo test",
		"-scryptn=10", "-plaintextnames", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
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
