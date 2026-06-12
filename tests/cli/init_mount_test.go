package cli

// Tests for the all-in-one "-init ... -mount ..." command line, which
// initializes a new filesystem and immediately mounts it in a single
// invocation. See main.go for the two-pass argument handling.

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// initMount runs a combined "-init ... CIPHERDIR -mount ... CIPHERDIR MOUNTPOINT"
// command. The mount section runs in the foreground (-fg) and notifies us
// via SIGUSR1 once the mount is ready.
//
// initExtra are extra arguments for the init section (before CIPHERDIR).
// mountExtra are extra arguments for the mount section (after "-mount", before
// CIPHERDIR and MOUNTPOINT).
//
// On success (mount ready) it returns a nil error and the running *exec.Cmd
// so the caller can unmount and wait. On failure it returns the error from
// the process and a nil *exec.Cmd.
func initMount(t *testing.T, initExtra []string, mountExtra []string) (cipherDir, mnt string, cmd *exec.Cmd, err error) {
	t.Helper()

	cipherDir = test_helpers.TmpDir + "/" + t.Name() + ".cipher"
	mnt = test_helpers.TmpDir + "/" + t.Name() + ".mnt"
	if err := os.MkdirAll(cipherDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mnt, 0700); err != nil {
		t.Fatal(err)
	}

	args := []string{"-q", "-init", "-scryptn=10"}
	args = append(args, initExtra...)
	args = append(args, cipherDir)
	args = append(args, "-mount", "-q", "-fg", "-nosyslog",
		"-notifypid="+strconv.Itoa(os.Getpid()))
	args = append(args, mountExtra...)
	args = append(args, cipherDir, mnt)

	cmd = exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	// The process sends us SIGUSR1 once the mount is ready, or exits on error.
	chanExit := make(chan error, 1)
	chanUsr1 := make(chan os.Signal, 1)
	signal.Notify(chanUsr1, syscall.SIGUSR1)
	defer signal.Stop(chanUsr1)

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		chanExit <- cmd.Wait()
	}()

	select {
	case err = <-chanExit:
		// Process exited before signalling success -> mount failed.
		return cipherDir, mnt, nil, err
	case <-chanUsr1:
		// Mount succeeded.
		return cipherDir, mnt, cmd, nil
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("timeout waiting for mount")
		return cipherDir, mnt, nil, nil
	}
}

// roundtrip writes a file through the mount and verifies it can be read back,
// and that an encrypted name shows up in the cipher dir.
func roundtrip(t *testing.T, cipherDir, mnt string) {
	t.Helper()
	plain := mnt + "/hello.txt"
	if err := os.WriteFile(plain, []byte("content"), 0600); err != nil {
		t.Errorf("write through mount failed: %v", err)
		return
	}
	got, err := os.ReadFile(plain)
	if err != nil {
		t.Errorf("read through mount failed: %v", err)
		return
	}
	if string(got) != "content" {
		t.Errorf("roundtrip mismatch: got %q", got)
	}
	// The cipher dir must contain the config plus at least one encrypted file.
	entries, err := os.ReadDir(cipherDir)
	if err != nil {
		t.Fatal(err)
	}
	nEncrypted := 0
	for _, e := range entries {
		switch e.Name() {
		case "gocryptfs.conf", "gocryptfs.diriv":
			// expected metadata
		default:
			nEncrypted++
		}
	}
	if nEncrypted == 0 {
		t.Errorf("no encrypted file found in cipher dir %q", cipherDir)
	}
}

// TestInitMountExtpassCarryover is the happy path: init with "-extpass",
// then mount. The password chosen during init is automatically reused for the
// mount, so no password source needs to be given in the mount phase.
func TestInitMountExtpassCarryover(t *testing.T) {
	cipherDir, mnt, cmd, err := initMount(t,
		[]string{"-extpass", "echo test"},
		nil)
	if err != nil {
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	}
	_ = cmd
	defer test_helpers.UnmountPanic(mnt)
	roundtrip(t, cipherDir, mnt)
}

// TestInitMountDoubleDashMount checks that the mount phase can be introduced
// with the double-dash form "--mount" (instead of "-mount"). The split that
// separates the init and mount command lines must recognize both spellings.
func TestInitMountDoubleDashMount(t *testing.T) {
	cipherDir := test_helpers.TmpDir + "/" + t.Name() + ".cipher"
	mnt := test_helpers.TmpDir + "/" + t.Name() + ".mnt"
	if err := os.MkdirAll(cipherDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mnt, 0700); err != nil {
		t.Fatal(err)
	}

	// Note "--mount" (double dash) instead of "-mount".
	args := []string{"-q", "-init", "-scryptn=10", "-extpass", "echo test", cipherDir,
		"--mount", "-q", "-fg", "-nosyslog",
		"-notifypid=" + strconv.Itoa(os.Getpid()), cipherDir, mnt}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	chanExit := make(chan error, 1)
	chanUsr1 := make(chan os.Signal, 1)
	signal.Notify(chanUsr1, syscall.SIGUSR1)
	defer signal.Stop(chanUsr1)

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		chanExit <- cmd.Wait()
	}()

	select {
	case err := <-chanExit:
		t.Fatalf("combined init + --mount should have succeeded, got: %v", err)
	case <-chanUsr1:
		// Mount succeeded.
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("timeout waiting for mount")
	}
	defer test_helpers.UnmountPanic(mnt)
	roundtrip(t, cipherDir, mnt)
}

// TestInitMountPassfileCarryover: init with "-passfile", then mount. The
// password read from the passfile during init is automatically reused for the
// mount, so no password source needs to be given in the mount phase.
func TestInitMountPassfileCarryover(t *testing.T) {
	passfile := test_helpers.TmpDir + "/" + t.Name() + ".pw.txt"
	if err := os.WriteFile(passfile, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	cipherDir, mnt, cmd, err := initMount(t,
		[]string{"-passfile=" + passfile},
		nil)
	if err != nil {
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	}
	_ = cmd
	defer test_helpers.UnmountPanic(mnt)
	roundtrip(t, cipherDir, mnt)
}

// TestInitMountMasterkeyCarryover: init with an explicit "-masterkey",
// mount reuses it via "-masterkey=init". A non-zero key is used so the
// carryover actually exercises copying the real key bytes.
func TestInitMountMasterkeyCarryover(t *testing.T) {
	// Non-zero 32-byte master key.
	const mk = "cf1b8f11-b52a146c-56e6bada-5468f572-6a7e7758-c2847ada-9d7c318c-8e32deb7"
	cipherDir, mnt, cmd, err := initMount(t,
		[]string{"-masterkey=" + mk, "-extpass", "echo test"},
		[]string{"-masterkey=init"})
	if err != nil {
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	}
	_ = cmd
	defer test_helpers.UnmountPanic(mnt)
	roundtrip(t, cipherDir, mnt)
}

// TestInitMountMasterkeyCarryoverGenerated: init without "-masterkey" (the key
// is randomly generated during config creation), mount reuses that generated
// key via "-masterkey=init".
func TestInitMountMasterkeyCarryoverGenerated(t *testing.T) {
	cipherDir, mnt, cmd, err := initMount(t,
		[]string{"-extpass", "echo test"},
		[]string{"-masterkey=init"})
	if err != nil {
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	}
	_ = cmd
	defer test_helpers.UnmountPanic(mnt)
	roundtrip(t, cipherDir, mnt)
}

// TestInitMountMasterkeyPersistence verifies the end-to-end masterkey
// carryover: it creates and mounts a filesystem in one command using an
// explicit master key (mount phase reuses it via "-masterkey=init"), writes a
// file, then unmounts by stopping the foreground process. It then remounts the
// *same* cipher dir with the same explicit master key and verifies the
// previously written file is present and readable. This proves the mount phase
// really used the init-phase master key (a wrong key would make the config
// undecryptable on remount, or the files unreadable).
func TestInitMountMasterkeyPersistence(t *testing.T) {
	// Non-zero 32-byte master key.
	const mk = "cf1b8f11-b52a146c-56e6bada-5468f572-6a7e7758-c2847ada-9d7c318c-8e32deb7"

	cipherDir := test_helpers.TmpDir + "/" + t.Name() + ".cipher"
	mnt := test_helpers.TmpDir + "/" + t.Name() + ".mnt"
	if err := os.MkdirAll(cipherDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mnt, 0700); err != nil {
		t.Fatal(err)
	}

	// Phase 1: all-in-one init + mount with explicit master key, mount reusing
	// it via "-masterkey=init", running in the foreground.
	args := []string{"-q", "-init", "-scryptn=10", "-masterkey=" + mk, "-extpass", "echo test", cipherDir,
		"-mount", "-q", "-fg", "-nosyslog", "-masterkey=init",
		"-notifypid=" + strconv.Itoa(os.Getpid()), cipherDir, mnt}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	chanExit := make(chan error, 1)
	chanUsr1 := make(chan os.Signal, 1)
	signal.Notify(chanUsr1, syscall.SIGUSR1)
	defer signal.Stop(chanUsr1)

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		chanExit <- cmd.Wait()
	}()

	select {
	case err := <-chanExit:
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	case <-chanUsr1:
		// Mount succeeded.
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("timeout waiting for mount")
	}

	// Write a file through the mount and verify the content.
	const fileName = "secret.txt"
	const fileContent = "the quick brown fox"
	if err := os.WriteFile(mnt+"/"+fileName, []byte(fileContent), 0600); err != nil {
		cmd.Process.Signal(syscall.SIGINT)
		t.Fatalf("write through mount failed: %v", err)
	}
	got, err := os.ReadFile(mnt + "/" + fileName)
	if err != nil {
		cmd.Process.Signal(syscall.SIGINT)
		t.Fatalf("read through mount failed: %v", err)
	}
	if string(got) != fileContent {
		cmd.Process.Signal(syscall.SIGINT)
		t.Fatalf("content mismatch: got %q want %q", got, fileContent)
	}

	// Stop the foreground gocryptfs process, which unmounts the filesystem.
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("failed to signal mount process: %v", err)
	}
	select {
	case <-chanExit:
		// Process exited (unmounted).
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("timeout waiting for unmount")
	}

	// After unmount the mountpoint must no longer expose the file.
	if _, err := os.Stat(mnt + "/" + fileName); !os.IsNotExist(err) {
		t.Errorf("file %q should be gone after unmount, stat err = %v", fileName, err)
	}

	// Phase 2: remount the same cipher dir with the same explicit master key.
	test_helpers.MountOrFatal(t, cipherDir, mnt, "-masterkey="+mk)
	defer test_helpers.UnmountPanic(mnt)

	// The file written during phase 1 must be present and readable.
	got, err = os.ReadFile(mnt + "/" + fileName)
	if err != nil {
		t.Fatalf("read after remount failed: %v", err)
	}
	if string(got) != fileContent {
		t.Errorf("content mismatch after remount: got %q want %q", got, fileContent)
	}
}

// TestInitMountPlaintextnames exercises the init-time "-plaintextnames" option
// through the all-in-one command line. With plaintext names enabled, file names
// are not encrypted, so the file written through the mount appears verbatim in
// the cipher dir, and no per-directory IV file (gocryptfs.diriv) is created.
func TestInitMountPlaintextnames(t *testing.T) {
	cipherDir, mnt, cmd, err := initMount(t,
		[]string{"-plaintextnames", "-extpass", "echo test"},
		nil)
	if err != nil {
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	}
	_ = cmd
	defer test_helpers.UnmountPanic(mnt)

	// Config must record the PlaintextNames feature flag.
	cf, err := configfile.Load(cipherDir + "/gocryptfs.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !cf.IsFeatureFlagSet(configfile.FlagPlaintextNames) {
		t.Errorf("PlaintextNames feature flag not set in config")
	}
	// Write a file; its name must appear unencrypted in the cipher dir.
	if err := os.WriteFile(mnt+"/myfile.txt", []byte("content"), 0600); err != nil {
		t.Fatalf("write through mount failed: %v", err)
	}
	if _, err := os.Stat(cipherDir + "/myfile.txt"); err != nil {
		t.Errorf("plaintext file name should appear in cipher dir: %v", err)
	}
	// With plaintextnames there is no gocryptfs.diriv.
	if _, err := os.Stat(cipherDir + "/gocryptfs.diriv"); !os.IsNotExist(err) {
		t.Errorf("gocryptfs.diriv should not exist with -plaintextnames, stat err = %v", err)
	}
}

// TestInitMountAESSIV exercises the init-time "-aessiv" option through the
// all-in-one command line and verifies the config records the AES-SIV backend.
func TestInitMountAESSIV(t *testing.T) {
	cipherDir, mnt, cmd, err := initMount(t,
		[]string{"-aessiv", "-extpass", "echo test"},
		nil)
	if err != nil {
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	}
	_ = cmd
	defer test_helpers.UnmountPanic(mnt)

	cf, err := configfile.Load(cipherDir + "/gocryptfs.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !cf.IsFeatureFlagSet(configfile.FlagAESSIV) {
		t.Errorf("AESSIV feature flag not set in config")
	}
	roundtrip(t, cipherDir, mnt)
}

// TestInitMountDeterministicNames exercises the init-time "-deterministic-names"
// option through the all-in-one command line. It disables the per-directory IV
// files, so DirIV is not set and no gocryptfs.diriv is created.
func TestInitMountDeterministicNames(t *testing.T) {
	cipherDir, mnt, cmd, err := initMount(t,
		[]string{"-deterministic-names", "-extpass", "echo test"},
		nil)
	if err != nil {
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	}
	_ = cmd
	defer test_helpers.UnmountPanic(mnt)

	cf, err := configfile.Load(cipherDir + "/gocryptfs.conf")
	if err != nil {
		t.Fatal(err)
	}
	if cf.IsFeatureFlagSet(configfile.FlagDirIV) {
		t.Errorf("DirIV feature flag should NOT be set with -deterministic-names")
	}
	if _, err := os.Stat(cipherDir + "/gocryptfs.diriv"); !os.IsNotExist(err) {
		t.Errorf("gocryptfs.diriv should not exist with -deterministic-names, stat err = %v", err)
	}
	roundtrip(t, cipherDir, mnt)
}

// TestInitMountLongnamemax exercises the init-time "-longnamemax" option through
// the all-in-one command line and verifies the chosen value is stored in the
// config and that a long file name still round-trips.
func TestInitMountLongnamemax(t *testing.T) {
	cipherDir, mnt, cmd, err := initMount(t,
		[]string{"-longnamemax", "100", "-extpass", "echo test"},
		nil)
	if err != nil {
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	}
	_ = cmd
	defer test_helpers.UnmountPanic(mnt)

	cf, err := configfile.Load(cipherDir + "/gocryptfs.conf")
	if err != nil {
		t.Fatal(err)
	}
	if cf.LongNameMax != 100 {
		t.Errorf("LongNameMax = %d, want 100", cf.LongNameMax)
	}
	// A long file name must still round-trip (it gets hashed into a
	// gocryptfs.longname.* entry on disk).
	longName := mnt + "/" + filepath.Base(t.Name()) + "_" +
		"this_is_a_fairly_long_file_name_that_exceeds_the_configured_longnamemax_limit.txt"
	if err := os.WriteFile(longName, []byte("content"), 0600); err != nil {
		t.Fatalf("write of long name through mount failed: %v", err)
	}
	got, err := os.ReadFile(longName)
	if err != nil {
		t.Fatalf("read of long name through mount failed: %v", err)
	}
	if string(got) != "content" {
		t.Errorf("long name roundtrip mismatch: got %q", got)
	}
}

// TestInitMountReadonly exercises the mount-time "-ro" option through the
// all-in-one command line: writes to the mount must be rejected.
func TestInitMountReadonly(t *testing.T) {
	_, mnt, cmd, err := initMount(t,
		[]string{"-extpass", "echo test"},
		[]string{"-ro"})
	if err != nil {
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	}
	_ = cmd
	defer test_helpers.UnmountPanic(mnt)

	if err := os.WriteFile(mnt+"/foo.txt", []byte("x"), 0600); err == nil {
		t.Errorf("write to read-only mount should have failed")
	}
}

// TestInitMountDashOReadonly exercises a mount-time option passed via the
// libfuse-style "-o COMMA-SEPARATED-OPTIONS" syntax ("-o ro") through the
// all-in-one command line: writes to the mount must be rejected.
func TestInitMountDashOReadonly(t *testing.T) {
	_, mnt, cmd, err := initMount(t,
		[]string{"-extpass", "echo test"},
		[]string{"-o", "ro"})
	if err != nil {
		t.Fatalf("combined init+mount should have succeeded, got: %v", err)
	}
	_ = cmd
	defer test_helpers.UnmountPanic(mnt)

	if err := os.WriteFile(mnt+"/foo.txt", []byte("x"), 0600); err == nil {
		t.Errorf("write to read-only (-o ro) mount should have failed")
	}
}

// TestInitMountReverse exercises reverse mode through the all-in-one command
// line. The init phase writes the reverse config into plainDir and the mount
// phase presents an encrypted view of plainDir at cipherDir.
func TestInitMountReverse(t *testing.T) {
	plainDir := test_helpers.TmpDir + "/" + t.Name() + ".plain"
	cipherDir := test_helpers.TmpDir + "/" + t.Name() + ".cipher"
	if err := os.MkdirAll(plainDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cipherDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Put a file into the plaintext dir so it shows up (encrypted) in the
	// reverse-mounted cipher view.
	if err := os.WriteFile(plainDir+"/hello.txt", []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}

	args := []string{"-q", "-reverse", "-init", "-scryptn=10", "-extpass", "echo test", plainDir,
		"-mount", "-reverse", "-q", "-fg", "-nosyslog",
		"-notifypid=" + strconv.Itoa(os.Getpid()), plainDir, cipherDir}

	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	chanExit := make(chan error, 1)
	chanUsr1 := make(chan os.Signal, 1)
	signal.Notify(chanUsr1, syscall.SIGUSR1)
	defer signal.Stop(chanUsr1)

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		chanExit <- cmd.Wait()
	}()

	select {
	case err := <-chanExit:
		t.Fatalf("combined reverse init+mount should have succeeded, got: %v", err)
	case <-chanUsr1:
		// Mount succeeded.
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("timeout waiting for mount")
	}
	defer test_helpers.UnmountPanic(cipherDir)

	// The reverse cipher view must expose an encrypted entry on top of the
	// virtual config/diriv metadata.
	entries, err := os.ReadDir(cipherDir)
	if err != nil {
		t.Fatal(err)
	}
	nEncrypted := 0
	for _, e := range entries {
		switch e.Name() {
		case "gocryptfs.conf", "gocryptfs.diriv":
			// expected virtual metadata
		default:
			nEncrypted++
		}
	}
	if nEncrypted == 0 {
		t.Errorf("no encrypted file found in reverse cipher view %q", cipherDir)
	}
}

// TestMountWithoutInitFails: using "-mount" without a preceding "-init" is
// rejected with exit code Usage.
func TestMountWithoutInitFails(t *testing.T) {
	// First create a filesystem normally so the cipher dir is valid.
	cipherDir := test_helpers.InitFS(t)
	mnt := cipherDir + ".mnt"
	if err := os.MkdirAll(mnt, 0700); err != nil {
		t.Fatal(err)
	}
	// "-mount" appears with no "-init" anywhere on the command line.
	args := []string{"-q", "-extpass", "echo test", cipherDir,
		"-mount", "-q", "-fg", mnt}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	err := cmd.Run()
	exitCode := test_helpers.ExtractCmdExitCode(err)
	if exitCode != exitcodes.Usage {
		t.Errorf("want exit code %d (Usage), got %d", exitcodes.Usage, exitCode)
	}
	// Make sure nothing got mounted.
	if isMounted(mnt) {
		test_helpers.UnmountPanic(mnt)
		t.Errorf("filesystem should not have been mounted")
	}
}

// TestMountWithoutArgsFails: specifying "-init ... -mount" with no arguments
// after "-mount" is rejected with exit code Usage.
func TestMountWithoutArgsFails(t *testing.T) {
	cipherDir := test_helpers.TmpDir + "/" + t.Name() + ".cipher"
	if err := os.MkdirAll(cipherDir, 0700); err != nil {
		t.Fatal(err)
	}
	// "-mount" is the last argument, with nothing following it.
	args := []string{"-q", "-init", "-scryptn=10", "-extpass", "echo test",
		cipherDir, "-mount"}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	err := cmd.Run()
	exitCode := test_helpers.ExtractCmdExitCode(err)
	if exitCode != exitcodes.Usage {
		t.Errorf("want exit code %d (Usage), got %d", exitcodes.Usage, exitCode)
	}
}

// TestInitMountBackground checks the all-in-one init+mount running in the
// BACKGROUND (no "-fg" in the mount section). The whole init+mount sequence is
// daemonized into a single child, so the launched command returns once the
// mount is ready and the in-memory password carry-over still works (no password
// source is given in the mount section).
func TestInitMountBackground(t *testing.T) {
	cipherDir := test_helpers.TmpDir + "/" + t.Name() + ".cipher"
	mnt := test_helpers.TmpDir + "/" + t.Name() + ".mnt"
	if err := os.MkdirAll(cipherDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mnt, 0700); err != nil {
		t.Fatal(err)
	}
	// No "-fg" in the mount section: the command daemonizes and returns 0
	// once the background mount is ready.
	args := []string{"-q", "-init", "-scryptn=10", "-extpass", "echo test",
		cipherDir, "-mount", "-q", "-nosyslog", cipherDir, mnt}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("background init+mount should have returned 0, got: %v", err)
	}
	if !isMounted(mnt) {
		t.Fatalf("filesystem is not mounted after background init+mount")
	}
	defer test_helpers.UnmountPanic(mnt)
	roundtrip(t, cipherDir, mnt)
}

// isMounted reports whether path is currently a mountpoint.
func isMounted(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	return exec.Command("mountpoint", "-q", abs).Run() == nil
}
