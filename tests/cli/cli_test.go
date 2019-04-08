package cli

// Test CLI operations like "-init", "-password" etc

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

var testPw = []byte("test")

func TestMain(m *testing.M) {
	test_helpers.ResetTmpDir(false)
	before := test_helpers.ListFds(0)
	r := m.Run()
	after := test_helpers.ListFds(0)
	if len(before) != len(after) {
		fmt.Printf("fd leak? before, after:\n%v\n%v\n", before, after)
		os.Exit(1)
	}
	os.Exit(r)
}

// Test -init flag
func TestInit(t *testing.T) {
	dir := test_helpers.InitFS(t)
	_, c, err := configfile.LoadAndDecrypt(dir+"/"+configfile.ConfDefaultName, testPw)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsFeatureFlagSet(configfile.FlagAESSIV) {
		t.Error("AESSIV flag should not be set")
	}
}

// Test that gocryptfs.conf and gocryptfs.diriv are there with the expected
// permissions after -init
func TestInitFilePerms(t *testing.T) {
	dir := test_helpers.InitFS(t)
	var st syscall.Stat_t
	syscall.Stat(dir+"/gocryptfs.conf", &st)
	perms := st.Mode & 0777
	if perms != 0400 {
		t.Errorf("Wrong permissions for gocryptfs.conf: %#o", perms)
	}
	st = syscall.Stat_t{}
	syscall.Stat(dir+"/gocryptfs.diriv", &st)
	perms = st.Mode & 0777
	// From v1.7.1, these are created with 0440 permissions, see
	// https://github.com/rfjakob/gocryptfs/issues/387
	if perms != 0440 {
		t.Errorf("Wrong permissions for gocryptfs.diriv: %#o", perms)
	}
}

// Test -init with -devrandom flag
func TestInitDevRandom(t *testing.T) {
	test_helpers.InitFS(t, "-devrandom")
}

// Test -init with -aessiv
func TestInitAessiv(t *testing.T) {
	dir := test_helpers.InitFS(t, "-aessiv")
	_, c, err := configfile.LoadAndDecrypt(dir+"/"+configfile.ConfDefaultName, testPw)
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
	_, c, err := configfile.LoadAndDecrypt(dir+"/"+configfile.ConfReverseName, testPw)
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
	args = []string{"-q", "-passwd"}
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
	mnt := dir + ".mnt"
	// Add content
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass", "echo test")
	file1 := mnt + "/file1"
	err := ioutil.WriteFile(file1, []byte("somecontent"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = test_helpers.UnmountErr(mnt)
	if err != nil {
		t.Fatal(err)
	}
	// Change password to "newpasswd"
	testPasswd(t, dir)
	// Mount and verify
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass", "echo newpasswd")
	content, err := ioutil.ReadFile(file1)
	if err != nil {
		t.Error(err)
	} else if string(content) != "somecontent" {
		t.Errorf("wrong content: %q", string(content))
	}
	err = test_helpers.UnmountErr(mnt)
	if err != nil {
		t.Fatal(err)
	}
}

// Test -passwd with -masterkey
func TestPasswdMasterkey(t *testing.T) {
	// Create FS
	dir := test_helpers.InitFS(t)
	// Overwrite with config with known master key
	conf, err := ioutil.ReadFile("gocryptfs.conf.b9e5ba23")
	if err != nil {
		t.Fatal(err)
	}
	syscall.Unlink(dir + "/gocryptfs.conf")
	err = ioutil.WriteFile(dir+"/gocryptfs.conf", conf, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// Add content
	mnt := dir + ".mnt"
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass", "echo test")
	file1 := mnt + "/file1"
	err = ioutil.WriteFile(file1, []byte("somecontent"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.UnmountPanic(mnt)
	// Change password using stdin
	args := []string{"-q", "-passwd", "-masterkey",
		"b9e5ba23-981a22b8-c8d790d8-627add29-f680513f-b7b7035f-d203fb83-21d82205"}
	args = append(args, dir)
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
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
	// New password
	p.Write([]byte("newpasswd\n"))
	p.Close()
	err = cmd.Wait()
	if err != nil {
		t.Error(err)
	}
	// Mount and verify
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass", "echo newpasswd")
	content, err := ioutil.ReadFile(file1)
	if err != nil {
		t.Error(err)
	} else if string(content) != "somecontent" {
		t.Errorf("wrong content: %q", string(content))
	}
	test_helpers.UnmountPanic(mnt)
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

// Test "-nonempty"
func TestNonempty(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	err := os.Mkdir(mnt, 0700)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(mnt+"/somefile", []byte("xyz"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = test_helpers.Mount(dir, mnt, false, "-extpass=echo test")
	if err == nil {
		t.Errorf("Mounting over a file should fail per default")
	}
	// Should work with "-nonempty"
	test_helpers.MountOrFatal(t, dir, mnt, "-nonempty", "-extpass=echo test")
	test_helpers.UnmountPanic(mnt)
}

// -nofail should be ignored and the mount should succeed
func TestNofail(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	test_helpers.MountOrFatal(t, dir, mnt, "-nofail", "-extpass=echo test")
	defer test_helpers.UnmountPanic(mnt)
}

// Test "mountpoint shadows cipherdir" handling
func TestShadows(t *testing.T) {
	mnt := test_helpers.InitFS(t)
	cipher := mnt + ".cipher"
	err := os.Rename(mnt, cipher)
	if err != nil {
		t.Fatal(err)
	}
	// This should work
	// (note that MountOrFatal creates "mnt" again)
	test_helpers.MountOrFatal(t, cipher, mnt, "-extpass=echo test")
	test_helpers.UnmountPanic(mnt)
	cipher2 := mnt + "/cipher"
	err = os.Rename(cipher, cipher2)
	if err != nil {
		t.Fatal(err)
	}
	// This should fail
	err = test_helpers.Mount(cipher2, mnt, false, "-extpass=echo test")
	if err == nil {
		t.Errorf("Should have failed")
	}
}

// TestMountPasswordIncorrect makes sure the correct exit code is used when the password
// was incorrect while mounting
func TestMountPasswordIncorrect(t *testing.T) {
	cDir := test_helpers.InitFS(t) // Create filesystem with password "test"
	pDir := cDir + ".mnt"
	err := test_helpers.Mount(cDir, pDir, false, "-extpass", "echo WRONG", "-wpanic=false")
	exitCode := test_helpers.ExtractCmdExitCode(err)
	if exitCode != exitcodes.PasswordIncorrect {
		t.Errorf("want=%d, got=%d", exitcodes.PasswordIncorrect, exitCode)
	}
}

// TestPasswdPasswordIncorrect makes sure the correct exit code is used when the password
// was incorrect while changing the password
func TestPasswdPasswordIncorrect(t *testing.T) {
	cDir := test_helpers.InitFS(t) // Create filesystem with password "test"
	// Change password
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-passwd", cDir)
	childStdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Start()
	if err != nil {
		t.Fatal(err)
	}
	_, err = childStdin.Write([]byte("WRONGPASSWORD\nNewPassword"))
	if err != nil {
		t.Fatal(err)
	}
	err = childStdin.Close()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	exitCode := test_helpers.ExtractCmdExitCode(err)
	if exitCode != exitcodes.PasswordIncorrect {
		t.Errorf("want=%d, got=%d", exitcodes.PasswordIncorrect, exitCode)
	}
}

// Check that we correctly background on mount and close stderr and stdout.
// Something like
//   gocryptfs a b | cat
// must not hang ( https://github.com/rfjakob/gocryptfs/issues/130 ).
func TestMountBackground(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	err := os.Mkdir(mnt, 0700)
	if err != nil {
		t.Fatal(err)
	}
	// Manually create a pipe pair and connect the child's stdout and stderr
	// to it. We cannot use StdoutPipe because that will close the pipe
	// when the child forks away.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-extpass", "echo test", dir, mnt}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = pw
	cmd.Stderr = pw
	err = cmd.Run()
	if err != nil {
		t.Error(err)
	}
	pw.Close()
	defer test_helpers.UnmountPanic(mnt)
	// Read until we get EOF.
	c1 := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 1000)
		for {
			_, err = pr.Read(buf)
			// We should get io.EOF when the child closes stdout
			// and stderr.
			if err != nil {
				pr.Close()
				c1 <- struct{}{}
				return
			}
		}
	}()
	select {
	case <-c1:
		return
	case <-time.After(time.Second * 5):
		t.Fatal("timeout")
	}
}

// Test that "gocryptfs -init -info CIPHERDIR" returns an error to the
// user. Only one operation flag is allowed.
func TestMultipleOperationFlags(t *testing.T) {
	// Test all combinations
	opFlags := []string{"-init", "-info", "-passwd", "-fsck"}
	for _, flag1 := range opFlags {
		var flag2 string
		for _, flag2 = range opFlags {
			if flag1 == flag2 {
				continue
			}
			args := []string{flag1, flag2, "/tmp"}
			//t.Logf("testing %v", args)
			cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
			err := cmd.Run()
			exitCode := test_helpers.ExtractCmdExitCode(err)
			if exitCode != exitcodes.Usage {
				t.Fatalf("this should have failed with code %d, but returned %d",
					exitcodes.Usage, exitCode)
			}
		}
	}
}

func TestNoexec(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	err := os.Mkdir(mnt, 0700)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass=echo test", "-noexec")
	defer test_helpers.UnmountPanic(mnt)
	sh := mnt + "/x.sh"
	content := `#!/bin/bash
echo hello
`
	err = ioutil.WriteFile(sh, []byte(content), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = exec.Command(sh).Run()
	exitCode := test_helpers.ExtractCmdExitCode(err)
	if exitCode != int(syscall.EACCES) {
		t.Errorf("got exitcode %d instead of EPERM (%d)", exitCode, syscall.EPERM)
	}
}

// Test that a missing argument to "-o" triggers exit code 1.
// See also cli_args_test.go for comprehensive tests of "-o" parsing.
func TestMissingOArg(t *testing.T) {
	cmd := exec.Command(test_helpers.GocryptfsBinary, "foo", "bar", "-o")
	err := cmd.Run()
	exitCode := test_helpers.ExtractCmdExitCode(err)
	if exitCode != exitcodes.Usage {
		t.Fatalf("this should have failed with code %d, but returned %d",
			exitcodes.Usage, exitCode)
	}
}

// -exclude must return an error in forward mode
func TestExcludeForward(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	err := test_helpers.Mount(dir, mnt, false, "-extpass", "echo test", "-exclude", "foo")
	if err == nil {
		t.Errorf("-exclude in forward mode should fail")
	}
	t.Log(err)
}

// Check that the config file can be read from a named pipe.
// Make sure bug https://github.com/rfjakob/gocryptfs/issues/258 does not come
// back.
func TestConfigPipe(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	err := os.Mkdir(mnt, 0700)
	if err != nil {
		t.Fatal(err)
	}
	bashLine := fmt.Sprintf("%s -q -extpass \"echo test\" -config <(cat %s/gocryptfs.conf) %s %s", test_helpers.GocryptfsBinary, dir, dir, mnt)
	cmd := exec.Command("bash", "-c", bashLine)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	err = cmd.Run()
	exitCode := test_helpers.ExtractCmdExitCode(err)
	if exitCode != 0 {
		t.Errorf("bash command\n%q\nresulted in exit code %d", bashLine, exitCode)
		return
	}
	test_helpers.UnmountPanic(mnt)
}

// Ciphertext dir and mountpoint contains a comma
// https://github.com/rfjakob/gocryptfs/issues/262
func TestComma(t *testing.T) {
	dir0 := test_helpers.InitFS(t)
	dir := dir0 + ",foo,bar"
	err := os.Rename(dir0, dir)
	if err != nil {
		t.Fatal(err)
	}
	mnt := dir + ".mnt"
	err = test_helpers.Mount(dir, mnt, false, "-extpass", "echo test", "-wpanic=0")
	if err != nil {
		t.Fatalf("Failed to mount %q on %q: %v", dir, mnt, err)
	}
	test_helpers.UnmountPanic(mnt)
}

// Mount with idle timeout 10ms and check that the process exits by itself
// within 5 seconds.
func TestIdle(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	err := os.Mkdir(mnt, 0700)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary,
		"-q", "-nosyslog", "-fg", "-extpass", "echo test", "-i", "10ms", dir, mnt)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(5*time.Second, func() {
		t.Error("timeout waiting for umount")
		cmd.Process.Kill()
	})
	err = cmd.Wait()
	timer.Stop()
	if err != nil {
		t.Error(err)
	}
}
