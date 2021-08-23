package cli

import (
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// Create "-xchacha" fs
func TestInitXchacha(t *testing.T) {
	cDir := test_helpers.InitFS(nil, "-xchacha")
	// Check config file sanity
	_, c, err := configfile.LoadAndDecrypt(cDir+"/"+configfile.ConfDefaultName, testPw)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if c.IsFeatureFlagSet(configfile.FlagGCMIV128) {
		t.Error("GCMIV128 flag should be off")
	}
	if !c.IsFeatureFlagSet(configfile.FlagXChaCha20Poly1305) {
		t.Error("XChaCha20Poly1305 flag should be on")
	}
	if !c.IsFeatureFlagSet(configfile.FlagHKDF) {
		t.Error("HKDF flag should be on")
	}
}

// Create and mount "-xchacha" fs, and see if we get the expected file sizes
// (xchacha has longer IVs).
func TestXchacha(t *testing.T) {
	cDir := test_helpers.InitFS(nil, "-xchacha", "-plaintextnames")
	pDir := cDir + ".mnt"
	test_helpers.MountOrExit(cDir, pDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(pDir)

	if err := ioutil.WriteFile(pDir+"/1byte", []byte("x"), 0700); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(cDir+"/1byte", &st); err != nil {
		t.Fatal(err)
	}
	// 2 byte version header + 16 byte file id + 192 bit xchacha iv + 1 byte payload + 16 byte mac
	if st.Size != 2+16+24+1+16 {
		t.Errorf("wrong size %d", st.Size)
	}

	// 1 MiB = 256 4kiB blocks
	if err := ioutil.WriteFile(pDir+"/1MiB", make([]byte, 1024*1024), 0700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(cDir+"/1MiB", &st); err != nil {
		t.Fatal(err)
	}
	// 2 byte version header + (16 byte file id + 192 bit xchacha iv + 4096 byte payload + 16 byte mac)*256
	if st.Size != 2+16+(24+4096+16)*256 {
		t.Errorf("wrong size %d", st.Size)
	}
}
