package integration_tests

// Test CLI operations like "-init", "-password" etc

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/configfile"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

// Test -init flag
func TestInit(t *testing.T) {
	dir := test_helpers.InitFS(t)
	_, err := os.Stat(filepath.Join(dir, configfile.ConfDefaultName))
	if err != nil {
		t.Fatal(err)
	}
}

// Test -passwd flag
func TestPasswd(t *testing.T) {
	// Create FS
	dir := test_helpers.InitFS(t)
	// Change password using "-extpass"
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-q", "-passwd", "-extpass", "echo test", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
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
	config := test_helpers.TmpDir + "TestInitConfig.conf"
	dir := test_helpers.InitFS(t, "-config="+config)

	_, err := os.Stat(config)
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

// Test -ro
func TestRo(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	test_helpers.MountOrFatal(t, dir, mnt, "-ro", "-extpass=echo test")
	defer test_helpers.Unmount(mnt)

	file := mnt + "/file"
	err := os.Mkdir(file, 0777)
	if err == nil {
		t.Errorf("Mkdir should have failed")
	}
	_, err = os.Create(file)
	if err == nil {
		t.Errorf("Create should have failed")
	}
}
