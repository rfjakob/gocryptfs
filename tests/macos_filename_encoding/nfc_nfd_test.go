package macos_filename_encoding

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/text/unicode/norm"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

var nfcName = norm.NFC.String("e\u0301") // é
var nfdName = norm.NFD.String("e\u0301") // e + combining acute accent

func TestCreateNFC_AccessNFD(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only test")
	}
	if nfcName == nfdName {
		t.Fatal("NFC and NFD names should be different")
	}
	test_helpers.ResetTmpDir(false)
	cipherDir := test_helpers.InitFS(t)
	mntDir := filepath.Join(test_helpers.TmpDir, "mnt")
	test_helpers.MountOrFatal(t, cipherDir, mntDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	// Create a file with an NFC name
	nfcPath := filepath.Join(mntDir, nfcName)
	err := os.WriteFile(nfcPath, []byte("content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file with NFC name: %v", err)
	}

	// Try to read it with an NFD name
	nfdPath := filepath.Join(mntDir, nfdName)
	content, err := os.ReadFile(nfdPath)
	if err != nil {
		t.Fatalf("Failed to read file with NFD name: %v", err)
	}
	if string(content) != "content" {
		t.Errorf("Wrong content: %q", string(content))
	}
}

func TestCreateNFD_AccessNFC(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only test")
	}
	if nfcName == nfdName {
		t.Fatal("NFC and NFD names should be different")
	}
	test_helpers.ResetTmpDir(false)
	cipherDir := test_helpers.InitFS(t)
	mntDir := filepath.Join(test_helpers.TmpDir, "mnt")
	test_helpers.MountOrFatal(t, cipherDir, mntDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	// Create a file with an NFD name
	nfdPath := filepath.Join(mntDir, nfdName)
	err := os.WriteFile(nfdPath, []byte("content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file with NFD name: %v", err)
	}

	// Try to read it with an NFC name
	nfcPath := filepath.Join(mntDir, nfcName)
	content, err := os.ReadFile(nfcPath)
	if err != nil {
		t.Fatalf("Failed to read file with NFC name: %v", err)
	}
	if string(content) != "content" {
		t.Errorf("Wrong content: %q", string(content))
	}
}
