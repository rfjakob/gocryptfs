package reverse_test

import (
	"os"
	"os/exec"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestConfigCustomInsideCipherdir verifies that a custom config file (-config)
// located inside CIPHERDIR is hidden from the encrypted reverse view instead of
// leaking there in encrypted form.
//
// Regression test for https://github.com/rfjakob/gocryptfs/issues/1009
func TestConfigCustomInsideCipherdir(t *testing.T) {
	backingDir, err := os.MkdirTemp(test_helpers.TmpDir, t.Name()+".")
	if err != nil {
		t.Fatal(err)
	}
	// A regular file that must stay visible in the encrypted view.
	if err := os.WriteFile(backingDir+"/secret.txt", []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	// The custom config file lives *inside* the backing dir.
	cfg := backingDir + "/my-custom.conf"

	// Init reverse fs with the config at the custom location.
	initArgs := []string{"-q", "-init", "-reverse", "-extpass", "echo test", "-scryptn=10", "-config", cfg}
	if plaintextnames {
		initArgs = append(initArgs, "-plaintextnames")
	} else if deterministic_names {
		initArgs = append(initArgs, "-deterministic-names")
	}
	initArgs = append(initArgs, backingDir)
	cmd := exec.Command(test_helpers.GocryptfsBinary, initArgs...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	mnt := backingDir + ".mnt"
	sock := mnt + ".sock"
	test_helpers.MountOrFatal(t, backingDir, mnt, "-reverse", "-extpass", "echo test",
		"-config", cfg, "-ctlsock", sock)
	defer test_helpers.UnmountPanic(mnt)

	// The custom config file must NOT show up (encrypted) in the view.
	cCfg := ctlsockEncryptPath(t, sock, "my-custom.conf")
	if test_helpers.VerifyExistence(t, mnt+"/"+cCfg) {
		t.Errorf("custom config %q is exposed in the encrypted view (as %q), but should be hidden", cfg, cCfg)
	}
	// With a custom config file, no virtual gocryptfs.conf is presented.
	if test_helpers.VerifyExistence(t, mnt+"/gocryptfs.conf") {
		t.Errorf("gocryptfs.conf should not be present in the view when -config is used")
	}
	// Regular files must remain visible.
	cSecret := ctlsockEncryptPath(t, sock, "secret.txt")
	if !test_helpers.VerifyExistence(t, mnt+"/"+cSecret) {
		t.Errorf("regular file secret.txt (as %q) is missing from the encrypted view", cSecret)
	}
}
