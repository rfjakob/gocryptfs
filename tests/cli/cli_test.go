// package cli tests CLI operations like "-init", "-password" etc
package cli

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

var testPw = []byte("test")

func TestMain(m *testing.M) {
	test_helpers.ResetTmpDir(false)
	before := test_helpers.ListFds(0, "")
	r := m.Run()
	after := test_helpers.ListFds(0, "")
	if len(before) != len(after) {
		fmt.Printf("fd leak in test process? before, after:\n%v\n%v\n", before, after)
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
	// https://github.com/rfjakob/gocryptfs/issues/387 .
	// From v2.0, created with 0444 perms, see
	// https://github.com/rfjakob/gocryptfs/issues/539 .
	if perms != 0444 {
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

// testPasswd changes the password from "test" to "test" using
// the -extpass method, then from "test" to "newpasswd" using the
// stdin method.
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

// cp copies file at `src` to `dst`, overwriting
// `dst` if it already exists. Calls t.Fatal on failure.
func cp(t *testing.T, src string, dst string) {
	conf, err := ioutil.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	syscall.Unlink(dst)
	err = ioutil.WriteFile(dst, conf, 0600)
	if err != nil {
		t.Fatal(err)
	}
}

// Test -passwd with -masterkey
func TestPasswdMasterkey(t *testing.T) {
	// Create FS
	dir := test_helpers.InitFS(t)
	// Overwrite with config with known master key
	cp(t, "gocryptfs.conf.b9e5ba23", dir+"/gocryptfs.conf")
	// Add content
	mnt := dir + ".mnt"
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass", "echo test")
	file1 := mnt + "/file1"
	err := ioutil.WriteFile(file1, []byte("somecontent"), 0600)
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

// Test -passwd with -masterkey=stdin
func TestPasswdMasterkeyStdin(t *testing.T) {
	// Create FS
	dir := test_helpers.InitFS(t)
	// Overwrite with config with known master key
	cp(t, "gocryptfs.conf.b9e5ba23", dir+"/gocryptfs.conf")
	// Add content
	mnt := dir + ".mnt"
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass", "echo test")
	file1 := mnt + "/file1"
	err := ioutil.WriteFile(file1, []byte("somecontent"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	test_helpers.UnmountPanic(mnt)
	// Change password using stdin
	args := []string{"-q", "-passwd", "-masterkey=stdin"}
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
	// Masterkey
	p.Write([]byte("b9e5ba23-981a22b8-c8d790d8-627add29-f680513f-b7b7035f-d203fb83-21d82205\n"))
	// New password
	p.Write([]byte("newpasswd\n"))
	p.Close()
	err = cmd.Wait()
	if err != nil {
		t.Fatal(err)
	}
	// Mount and verify
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass", "echo newpasswd")
	content, err := ioutil.ReadFile(file1)
	if err != nil {
		t.Fatal(err)
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

// Test -passwd with -scryptn
func TestPasswdScryptn(t *testing.T) {
	dir := test_helpers.InitFS(t)
	cf, err := configfile.Load(dir + "/gocryptfs.conf")
	if err != nil {
		t.Fatal(err)
	}
	testPasswd(t, dir, "-scryptn", strconv.Itoa(cf.ScryptObject.LogN()+1))
	cf2, err := configfile.Load(dir + "/gocryptfs.conf")
	if err != nil {
		t.Fatal(err)
	}
	if cf2.ScryptObject.LogN() != cf.ScryptObject.LogN()+1 {
		t.Errorf("wrong logN value %d", cf2.ScryptObject.LogN())
	}
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
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass=echo test", "-noexec")
	defer test_helpers.UnmountPanic(mnt)
	sh := mnt + "/x.sh"
	content := `#!/bin/bash
echo hello
`
	err := ioutil.WriteFile(sh, []byte(content), 0755)
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

// Mount with idle timeout of 100ms read something every 10ms. The fs should
// NOT get unmounted. Regression test for https://github.com/rfjakob/gocryptfs/issues/421
func TestNotIdle(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	err := test_helpers.Mount(dir, mnt, false, "-extpass", "echo test", "-i=100ms")
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(mnt+"/foo", []byte("foo"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	// Read every 10 milliseconds for a total of 1 second
	for i := 1; i < 100; i++ {
		_, err = ioutil.ReadFile(mnt + "/foo")
		if err != nil {
			t.Fatalf("iteration %d failed: %v", i, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Keep a file handle open for 1 second
	fd, err := os.Open(mnt + "/foo")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Second)
	buf := make([]byte, 100)
	_, err = fd.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	// All good.
	test_helpers.UnmountPanic(mnt)
}

// TestSymlinkedCipherdir checks that if CIPHERDIR itself is a symlink, it is
// followed.
// https://github.com/rfjakob/gocryptfs/issues/450
func TestSymlinkedCipherdir(t *testing.T) {
	dir := test_helpers.InitFS(t)
	dirSymlink := dir + ".symlink"
	err := os.Symlink(dir, dirSymlink)
	if err != nil {
		t.Fatal(err)
	}
	mnt := dir + ".mnt"
	test_helpers.MountOrFatal(t, dirSymlink, mnt, "-extpass=echo test")
	defer test_helpers.UnmountPanic(mnt)

	file := mnt + "/file"
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	f, err = os.Open(mnt)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	names, err := f.Readdirnames(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "file" {
		t.Errorf("wrong Readdirnames result: %v", names)
	}
}

// TestBadname tests the `-badname` option
//
// Supported structure of badname: <ciphername><badname pattern><badname suffix>
// "Visible" shows the success of function DecryptName (cipher -> plain)
// "Access" shows the success of function EncryptAndHashBadName (plain -> cipher)
// Case    Visible  Access  Description
// Case 1     x       x     Access file without BadName suffix (default mode)
// Case 2     x       x     Access file with BadName suffix which has a valid cipher file (will only be possible if file was created without badname option)
// Case 3                   Access file with valid ciphername + BadName suffix (impossible since this would not be produced by DecryptName)
// Case 4     x       x     Access file with decryptable part of name and Badname suffix (default badname case)
// Case 5     x       x     Access file with undecryptable name and BadName suffix (e. g. when part of the cipher name was cut)
// Case 6     x             Access file with multiple possible matches.
// Case 7                   Access file with BadName suffix and non-matching pattern
func TestBadname(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	validFileName := "file"
	invalidSuffix := "_invalid_file"
	var contentCipher [7][]byte
	//first mount without badname (see case 2)
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass=echo test", "-wpanic=false")

	file := mnt + "/" + validFileName
	// Case 1: write one valid filename (empty content)
	err := ioutil.WriteFile(file, nil, 0600)
	if err != nil {
		t.Fatal(err)
	}

	// read encrypted file name
	fread, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fread.Close()
	encryptedfilename := ""
	ciphernames, err := fread.Readdirnames(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, ciphername := range ciphernames {
		if ciphername != "gocryptfs.conf" && ciphername != "gocryptfs.diriv" {
			encryptedfilename = ciphername
			// found cipher name of "file"
			break
		}
	}
	//Generate valid cipherdata for all cases
	for i := 0; i < len(contentCipher); i++ {
		err := ioutil.WriteFile(file, []byte(fmt.Sprintf("Content Case %d.", i+1)), 0600)
		if err != nil {
			t.Fatal(err)
		}
		//save the cipher data for file operations in cipher dir
		contentCipher[i], err = ioutil.ReadFile(dir + "/" + encryptedfilename)
		if err != nil {
			t.Fatal(err)
		}
	}

	//re-write content for case 1
	err = ioutil.WriteFile(file, []byte("Content Case 1."), 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Case 2: File with invalid suffix in plain name but valid cipher file
	file = mnt + "/" + validFileName + nametransform.BadnameSuffix
	err = ioutil.WriteFile(file, []byte("Content Case 2."), 0600)
	if err != nil {
		t.Fatal(err)
	}
	// unmount...
	test_helpers.UnmountPanic(mnt)

	// ...and remount with -badname.
	test_helpers.MountOrFatal(t, dir, mnt, "-badname=*valid*", "-extpass=echo test", "-wpanic=false")
	defer test_helpers.UnmountPanic(mnt)

	// Case 3 is impossible: only BadnameSuffix would mean the cipher name is valid

	// Case 4: write invalid file which should be decodable
	err = ioutil.WriteFile(dir+"/"+encryptedfilename+invalidSuffix, contentCipher[3], 0600)
	if err != nil {
		t.Fatal(err)
	}
	//Case 5: write invalid file which is not decodable (replace last 2 bytes with percent sign)
	err = ioutil.WriteFile(dir+"/"+encryptedfilename[:len(encryptedfilename)-2]+"%%"+invalidSuffix, contentCipher[4], 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Case 6: Multiple possible matches
	// generate two files with invalid cipher names which can both match the badname pattern
	err = ioutil.WriteFile(dir+"/mzaZRF9_0IU-_5vv2wPC"+invalidSuffix, contentCipher[5], 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(dir+"/mzaZRF9_0IU-_5vv2wP"+invalidSuffix, contentCipher[5], 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Case 7: Non-Matching badname pattern
	err = ioutil.WriteFile(dir+"/"+encryptedfilename+"wrongPattern", contentCipher[6], 0600)
	if err != nil {
		t.Fatal(err)
	}

	// check for filenames
	f, err := os.Open(mnt)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	names, err := f.Readdirnames(0)
	if err != nil {
		t.Fatal(err)
	}

	searchstrings := []string{
		validFileName,
		validFileName + nametransform.BadnameSuffix,
		"",
		validFileName + invalidSuffix + nametransform.BadnameSuffix,
		encryptedfilename[:len(encryptedfilename)-2] + "%%" + invalidSuffix + nametransform.BadnameSuffix,
		"",
		validFileName + "wrongPattern" + nametransform.BadnameSuffix}
	results := []bool{false, false, true, false, false, true, true}
	var filecontent string
	var filebytes []byte
	for _, name := range names {
		if name == searchstrings[0] {
			//Case 1: Test access
			filebytes, err = ioutil.ReadFile(mnt + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			filecontent = string(filebytes)
			if filecontent == "Content Case 1." {
				results[0] = true
			}

		} else if name == searchstrings[1] {
			//Case 2: Test Access
			filebytes, err = ioutil.ReadFile(mnt + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			filecontent = string(filebytes)
			if filecontent == "Content Case 2." {
				results[1] = true
			}
		} else if name == searchstrings[3] {
			//Case 4: Test Access
			filebytes, err = ioutil.ReadFile(mnt + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			filecontent = string(filebytes)
			if filecontent == "Content Case 4." {
				results[3] = true
			}
		} else if name == searchstrings[4] {
			//Case 5: Test Access
			filebytes, err = ioutil.ReadFile(mnt + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			filecontent = string(filebytes)
			if filecontent == "Content Case 5." {
				results[4] = true
			}
		} else if name == searchstrings[6] {
			//Case 7
			results[6] = false
		}
		//Case 3 is always passed
		//Case 6 is highly obscure:
		//The last part of a valid cipher name must match the badname pattern AND
		//the remaining cipher name must still be decryptable. Test case not programmable in a general case
	}

	for i := 0; i < len(results); i++ {
		if !results[i] {
			t.Errorf("Case %d failed: %q in [%q]", i+1, searchstrings[i], strings.Join(names, ","))
		}
	}
}

// TestPassfile tests the `-passfile` option
func TestPassfile(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	passfile1 := mnt + ".1.txt"
	ioutil.WriteFile(passfile1, []byte("test"), 0600)
	test_helpers.MountOrFatal(t, dir, mnt, "-passfile="+passfile1)
	defer test_helpers.UnmountPanic(mnt)
}

// TestPassfileX2 tests that the `-passfile` option can be passed twice
func TestPassfileX2(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	passfile1 := mnt + ".1.txt"
	passfile2 := mnt + ".2.txt"
	ioutil.WriteFile(passfile1, []byte("te"), 0600)
	ioutil.WriteFile(passfile2, []byte("st"), 0600)
	test_helpers.MountOrFatal(t, dir, mnt, "-passfile="+passfile1, "-passfile="+passfile2)
	defer test_helpers.UnmountPanic(mnt)
}

// TestInitNotEmpty checks that `gocryptfs -init` returns the right error code
// if CIPHERDIR is not empty. See https://github.com/rfjakob/gocryptfs/pull/503
func TestInitNotEmpty(t *testing.T) {
	dir := test_helpers.TmpDir + "/" + t.Name()
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(dir+"/foo", nil, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-init", "-extpass", "echo test", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	exitCode := test_helpers.ExtractCmdExitCode(err)
	if exitCode != exitcodes.CipherDir {
		t.Fatalf("wrong exit code: have=%d, want=%d", exitCode, exitcodes.CipherDir)
	}
}

// TestSharedstorage checks that `-sharedstorage` shows stable inode numbers to
// userpsace despite having hard link tracking disabled
func TestSharedstorage(t *testing.T) {
	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"
	test_helpers.MountOrFatal(t, dir, mnt, "-extpass=echo test", "-sharedstorage")
	defer test_helpers.UnmountPanic(mnt)
	foo1 := mnt + "/foo1"
	foo2 := mnt + "/foo2"
	if err := ioutil.WriteFile(foo1, nil, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(foo1, foo2); err != nil {
		t.Fatal(err)
	}
	var st1, st2 syscall.Stat_t
	if err := syscall.Stat(foo1, &st1); err != nil {
		t.Fatal(err)
	}
	// The link show show a new inode number
	if err := syscall.Stat(foo2, &st2); err != nil {
		t.Fatal(err)
	}
	if st1.Ino != st2.Ino {
		t.Errorf("unstable inode number: changed from %d to %d", st1.Ino, st2.Ino)
	}
	// Check that we we don't have stat caching. New length should show up
	// on the hard link immediately.
	if err := ioutil.WriteFile(foo1, []byte("xxxxxx"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(foo2, &st2); err != nil {
		t.Fatal(err)
	}
	if st2.Size != 6 {
		t.Fatal(st2.Size)
	}
}

// Test that the filesystem is immediately ready for Creat() after mount returns
func TestMountCreat(t *testing.T) {
	const concurrency = 2
	const repeat = 2

	dir := test_helpers.InitFS(t)
	mnt := dir + ".mnt"

	for j := 0; j < repeat; j++ {
		test_helpers.MountOrFatal(t, dir, mnt, "-extpass=echo test")
		var wg sync.WaitGroup
		wg.Add(concurrency)
		for i := 0; i < concurrency; i++ {
			go func(i int) {
				path := fmt.Sprintf("%s/%d", mnt, i)
				fd, err := syscall.Creat(path, 0600)
				syscall.Close(fd)
				if err != nil {
					t.Errorf("Creat %q: %v", path, err)
				}
				wg.Done()
			}(i)
		}
		wg.Wait()
		test_helpers.UnmountPanic(mnt)
	}
}
