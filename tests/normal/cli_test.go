package normal

// Test CLI operations like "-init", "-password" etc

import (
	"os"
	"os/exec"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/configfile"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func TestMain(m *testing.M) {
	test_helpers.ResetTmpDir(false)
	test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, "--zerokey")
	r := m.Run()
	test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
	os.Exit(r)
}

// Test -init flag
func TestInit(t *testing.T) {
	dir := test_helpers.InitFS(t)
	_, c, err := configfile.LoadConfFile(dir+"/"+configfile.ConfDefaultName, "test")
	if err != nil {
		t.Fatal(err)
	}
	if c.IsFeatureFlagSet(configfile.FlagAESSIV) {
		t.Error("AESSIV flag should not be set")
	}
}

// Test -init with -aessiv
func TestInitAessiv(t *testing.T) {
	dir := test_helpers.InitFS(t, "-aessiv")
	_, c, err := configfile.LoadConfFile(dir+"/"+configfile.ConfDefaultName, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsFeatureFlagSet(configfile.FlagAESSIV) {
		t.Error("AESSIV flag should be set but is not")
	}
}

// Test -init with -reverse
func TestInitReverse(t *testing.T) {
	dir := test_helpers.InitFS(t, "-reverse")
	_, c, err := configfile.LoadConfFile(dir+"/"+configfile.ConfReverseName, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsFeatureFlagSet(configfile.FlagAESSIV) {
		t.Error("AESSIV flag should be set but is not")
	}
}

func testPasswd(t *testing.T, dir string, extraArgs ...string) {
	// Change password using "-extpass"
	args := []string{"-q", "-passwd", "-extpass", "echo test"}
	args = append(args, extraArgs...)
	args = append(args, dir)
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		t.Error(err)
	}
	// Change password using stdin
	args = []string{"-q", "-passwd", "-extpass", "echo test"}
	args = append(args, extraArgs...)
	args = append(args, dir)
	cmd = exec.Command(test_helpers.GocryptfsBinary, args...)
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

// Test -passwd flag
func TestPasswd(t *testing.T) {
	// Create FS
	dir := test_helpers.InitFS(t)
	testPasswd(t, dir)
}

// Test -passwd with -reverse
func TestPasswdReverse(t *testing.T) {
	// Create FS
	dir := test_helpers.InitFS(t, "-reverse")
	testPasswd(t, dir, "-reverse")
}

// Test -init & -config flag
func TestInitConfig(t *testing.T) {
	config := test_helpers.TmpDir + "/TestInitConfig.conf"
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
	defer test_helpers.UnmountPanic(mnt)

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
