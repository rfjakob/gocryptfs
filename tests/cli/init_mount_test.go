package cli

// Integration tests for the combined "-init ... -mount ..." invocation.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// isMountPoint reports whether path currently appears as a mount in
// /proc/mounts.
func isMountPoint(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	buf, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(buf), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == abs {
			return true
		}
	}
	return false
}

// initMountDirs creates a fresh empty cipherdir and plaindir for a test and
// returns their paths.
func initMountDirs(t *testing.T) (cipherdir, plaindir string) {
	t.Helper()
	base := filepath.Join(test_helpers.TmpDir, t.Name())
	cipherdir = base + ".cipher"
	plaindir = base + ".plain"
	if err := os.MkdirAll(cipherdir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(plaindir, 0755); err != nil {
		t.Fatal(err)
	}
	return cipherdir, plaindir
}

// TestInitMountCombined runs a combined init+mount (daemonized) and verifies the
// filesystem is initialized and usable.
func TestInitMountCombined(t *testing.T) {
	cipherdir, plaindir := initMountDirs(t)

	args := []string{
		"-init", "-q", "-scryptn=10", "-extpass", "echo test", cipherdir,
		"-mount", "-extpass", "echo test", plaindir,
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("combined init+mount failed: %v", err)
	}
	defer test_helpers.UnmountErr(plaindir)

	// Config file must exist and decrypt with the init password.
	configPath := filepath.Join(cipherdir, configfile.ConfDefaultName)
	if _, _, err := configfile.LoadAndDecrypt(configPath, testPw); err != nil {
		t.Fatalf("could not load config created by combined init: %v", err)
	}

	// The mount must be usable.
	fn := filepath.Join(plaindir, "hello.txt")
	if err := os.WriteFile(fn, []byte("combined"), 0600); err != nil {
		t.Fatalf("write to mount failed: %v", err)
	}
	content, err := os.ReadFile(fn)
	if err != nil || string(content) != "combined" {
		t.Fatalf("read back failed: content=%q err=%v", content, err)
	}
}

// TestInitMountPasswordReuse verifies that the password entered on stdin during
// the init phase is reused for the mount phase (no -extpass in the mount part).
func TestInitMountPasswordReuse(t *testing.T) {
	cipherdir, plaindir := initMountDirs(t)

	args := []string{
		"-init", "-q", "-scryptn=10", cipherdir,
		"-mount", plaindir,
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// The init phase reads this password from stdin; it is then reused for mount.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(stdin, "test")
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("combined init+mount with stdin password failed: %v", err)
	}
	defer test_helpers.UnmountErr(plaindir)

	// Config must decrypt with the password we typed.
	configPath := filepath.Join(cipherdir, configfile.ConfDefaultName)
	if _, _, err := configfile.LoadAndDecrypt(configPath, testPw); err != nil {
		t.Fatalf("could not load config: %v", err)
	}
	// Mount must be usable, proving the password was reused successfully.
	fn := filepath.Join(plaindir, "reuse.txt")
	if err := os.WriteFile(fn, []byte("x"), 0600); err != nil {
		t.Fatalf("write to mount failed: %v", err)
	}
}

// TestInitMountSeparateOptions verifies that init-only options (here -aessiv)
// apply to the init phase and the resulting filesystem still mounts.
func TestInitMountSeparateOptions(t *testing.T) {
	cipherdir, plaindir := initMountDirs(t)

	args := []string{
		"-init", "-q", "-scryptn=10", "-aessiv", "-extpass", "echo test", cipherdir,
		"-mount", "-extpass", "echo test", plaindir,
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("combined init+mount failed: %v", err)
	}
	defer test_helpers.UnmountErr(plaindir)

	configPath := filepath.Join(cipherdir, configfile.ConfDefaultName)
	_, c, err := configfile.LoadAndDecrypt(configPath, testPw)
	if err != nil {
		t.Fatalf("could not load config: %v", err)
	}
	if !c.IsFeatureFlagSet(configfile.FlagAESSIV) {
		t.Error("AESSIV flag should be set (was passed in the -init section)")
	}
}

// TestInitMountOrderError verifies that "-mount" before "-init" is rejected.
func TestInitMountOrderError(t *testing.T) {
	cipherdir, plaindir := initMountDirs(t)

	args := []string{
		"-mount", plaindir,
		"-init", "-q", "-scryptn=10", "-extpass", "echo test", cipherdir,
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error when -mount precedes -init")
	}
	if code := test_helpers.ExtractCmdExitCode(err); code != exitcodes.Usage {
		t.Errorf("wrong exit code: want=%d (Usage), got=%d", exitcodes.Usage, code)
	}
	// Nothing should have been mounted.
	if isMountPoint(plaindir) {
		t.Error("plaindir should not be mounted")
		test_helpers.UnmountErr(plaindir)
	}
}

// TestInitMountWithoutInit verifies that "-mount" without "-init" is rejected.
func TestInitMountWithoutInit(t *testing.T) {
	_, plaindir := initMountDirs(t)

	cmd := exec.Command(test_helpers.GocryptfsBinary, "-mount", plaindir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error when -mount is used without -init")
	}
	if code := test_helpers.ExtractCmdExitCode(err); code != exitcodes.Usage {
		t.Errorf("wrong exit code: want=%d (Usage), got=%d", exitcodes.Usage, code)
	}
}

// TestInitMountInitFailsNoMount verifies that if the init phase fails (e.g. the
// cipherdir is not empty) the program exits and the mount phase is not run.
func TestInitMountInitFailsNoMount(t *testing.T) {
	cipherdir, plaindir := initMountDirs(t)
	// Make the cipherdir non-empty so init fails.
	if err := os.WriteFile(filepath.Join(cipherdir, "occupied"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	args := []string{
		"-init", "-q", "-scryptn=10", "-extpass", "echo test", cipherdir,
		"-mount", "-extpass", "echo test", plaindir,
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected init to fail on a non-empty cipherdir")
	}
	if code := test_helpers.ExtractCmdExitCode(err); code != exitcodes.CipherDir {
		t.Errorf("wrong exit code: want=%d (CipherDir), got=%d", exitcodes.CipherDir, code)
	}
	if isMountPoint(plaindir) {
		t.Error("mount phase must not run after init failure")
		test_helpers.UnmountErr(plaindir)
	}
}

// mkMasterkey returns a 32-byte masterkey filled with the given byte value and
// its hex-string representation.
func mkMasterkey(fill byte) (raw []byte, hexStr string) {
	raw = make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	return raw, hex.EncodeToString(raw)
}

// TestInitMountMasterkeyReuse verifies that a bare "-masterkey" in the mount
// section reuses the "-masterkey <key>" value given in the init section.
//
// To prove the reused key actually matches the freshly initialized filesystem,
// we write a file through the combined mount, unmount, then re-mount with the
// password (which uses the key stored in the config) and read the file back.
func TestInitMountMasterkeyReuse(t *testing.T) {
	cipherdir, plaindir := initMountDirs(t)
	mkRaw, mkHex := mkMasterkey(0x11)

	args := []string{
		"-init", "-q", "-scryptn=10", "-extpass", "echo test", "-masterkey=" + mkHex, cipherdir,
		"-mount", "-masterkey", plaindir,
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("combined init+mount with masterkey reuse failed: %v", err)
	}

	// The config must wrap exactly the masterkey we passed to -init.
	configPath := filepath.Join(cipherdir, configfile.ConfDefaultName)
	gotMk, _, err := configfile.LoadAndDecrypt(configPath, testPw)
	if err != nil {
		t.Fatalf("could not load config: %v", err)
	}
	if !bytes.Equal(gotMk, mkRaw) {
		t.Fatalf("config masterkey does not match the one passed to -init")
	}

	// Write a file through the combined mount (uses the reused key).
	if err := os.WriteFile(filepath.Join(plaindir, "secret.txt"), []byte("reuse"), 0600); err != nil {
		t.Fatalf("write to mount failed: %v", err)
	}
	if err := test_helpers.UnmountErr(plaindir); err != nil {
		t.Fatalf("unmount failed: %v", err)
	}

	// Re-mount using the password (config-based key) and read the file back.
	// This only succeeds if the reused key matched the filesystem.
	test_helpers.MountOrFatal(t, cipherdir, plaindir, "-extpass", "echo test")
	defer test_helpers.UnmountErr(plaindir)
	content, err := os.ReadFile(filepath.Join(plaindir, "secret.txt"))
	if err != nil || string(content) != "reuse" {
		t.Fatalf("read back via password mount failed: content=%q err=%v", content, err)
	}
}

// TestInitMountMasterkeySameValue verifies that an explicit "-masterkey=<key>"
// in the mount section that matches the init value mounts successfully.
func TestInitMountMasterkeySameValue(t *testing.T) {
	cipherdir, plaindir := initMountDirs(t)
	mkRaw, mkHex := mkMasterkey(0x22)

	args := []string{
		"-init", "-q", "-scryptn=10", "-extpass", "echo test", "-masterkey=" + mkHex, cipherdir,
		"-mount", "-masterkey=" + mkHex, plaindir,
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("combined init+mount with matching masterkey failed: %v", err)
	}
	defer test_helpers.UnmountErr(plaindir)

	configPath := filepath.Join(cipherdir, configfile.ConfDefaultName)
	gotMk, _, err := configfile.LoadAndDecrypt(configPath, testPw)
	if err != nil {
		t.Fatalf("could not load config: %v", err)
	}
	if !bytes.Equal(gotMk, mkRaw) {
		t.Fatalf("config masterkey does not match the one passed to -init")
	}
	if !isMountPoint(plaindir) {
		t.Fatal("filesystem should be mounted")
	}
	if err := os.WriteFile(filepath.Join(plaindir, "x.txt"), []byte("x"), 0600); err != nil {
		t.Fatalf("write to mount failed: %v", err)
	}
}

// TestInitMountMasterkeyDifferentValue verifies that an explicit
// "-masterkey=<key>" in the mount section that differs from the init value is
// rejected: the combined call fails and nothing is mounted.
func TestInitMountMasterkeyDifferentValue(t *testing.T) {
	cipherdir, plaindir := initMountDirs(t)
	_, initHex := mkMasterkey(0x33)
	_, mountHex := mkMasterkey(0x44) // different key

	args := []string{
		"-init", "-q", "-scryptn=10", "-extpass", "echo test", "-masterkey=" + initHex, cipherdir,
		"-mount", "-masterkey=" + mountHex, plaindir,
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected failure when the mount masterkey differs from the init masterkey")
	}
	if code := test_helpers.ExtractCmdExitCode(err); code != exitcodes.MasterKey {
		t.Errorf("wrong exit code: want=%d (MasterKey), got=%d", exitcodes.MasterKey, code)
	}
	if isMountPoint(plaindir) {
		t.Error("filesystem must not be mounted when masterkeys differ")
		test_helpers.UnmountErr(plaindir)
	}
}

// TestInitMountMasterkeyReuseWithoutInitKey verifies that a bare "-masterkey" in
// the mount section without a "-masterkey <key>" in the init section is a usage
// error.
func TestInitMountMasterkeyReuseWithoutInitKey(t *testing.T) {
	cipherdir, plaindir := initMountDirs(t)

	args := []string{
		"-init", "-q", "-scryptn=10", "-extpass", "echo test", cipherdir,
		"-mount", "-masterkey", plaindir,
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected failure when -mount uses bare -masterkey without an init masterkey")
	}
	if code := test_helpers.ExtractCmdExitCode(err); code != exitcodes.Usage {
		t.Errorf("wrong exit code: want=%d (Usage), got=%d", exitcodes.Usage, code)
	}
	if isMountPoint(plaindir) {
		t.Error("filesystem must not be mounted")
		test_helpers.UnmountErr(plaindir)
	}
}
